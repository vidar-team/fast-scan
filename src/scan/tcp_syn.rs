use crate::{
    error::{Error, Result},
    interface::Interface,
    worker::{AtomicState, State, Worker},
};
use flume::TryRecvError;
use ipnet::IpNet;
use log::{debug, error};
use pnet::{
    packet::{
        FromPacket, Packet,
        ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket},
    },
    util::MacAddr,
};
use rayon::ThreadPool;
use scopeguard::defer;
use std::{
    collections::HashMap,
    iter,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const CLOSED: u8 = TcpFlags::ACK | TcpFlags::RST;
const OPENED: u8 = TcpFlags::ACK | TcpFlags::SYN;

pub struct Scanner<'a> {
    pub pool: &'a ThreadPool,
    pub if_index: u32,
    pub dest_nets: Vec<IpNet>,
    pub dest_ports: Vec<u16>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub timeout: Duration,
    pub send_buffer_size: usize,
    pub recv_progress_tx: Option<flume::Sender<(IpAddr, u8, u16)>>,
    pub send_progress_tx: Option<flume::Sender<(IpAddr, u16)>>,
}

#[derive(Debug, Clone)]
pub struct Scanned {
    pub opened: Vec<u16>,
    pub closed: Vec<u16>,
    pub unknown: Vec<u16>,
}

struct Sender {
    dest_ips: Vec<IpAddr>,
    dest_ports: Vec<u16>,
    src_ip: IpAddr,
    src_port: u16,
    src_mac: MacAddr,
    gateway_mac: MacAddr,
    ttl: u8,
    progress_tx: Option<flume::Sender<(IpAddr, u16)>>,
}

struct Receiver {
    dest_ips: Vec<IpAddr>,
    dest_ports: Vec<u16>,
    state: Arc<AtomicState>,
    state_changed_on: Arc<AtomicU64>,
    time: Instant,
    timeout: Duration,
    progress_tx: Option<flume::Sender<(IpAddr, u8, u16)>>,
    result_tx: flume::Sender<Result<HashMap<IpAddr, Scanned>>>,
}

impl<'a> Scanner<'a> {
    pub fn build_bpf(&self) -> Result<String> {
        let dest_nets_filter = self
            .dest_nets
            .iter()
            .map(|net| format!("src net {}", net))
            .collect::<Vec<_>>()
            .join(" or ");

        Ok(match self.src_ip {
            IpAddr::V4(_) => format!(
                r"({}) and dst host {} and dst port {} and (tcp[tcpflags] & tcp-ack != 0)",
                dest_nets_filter, self.src_ip, self.src_port
            ),
            IpAddr::V6(_) => format!(
                r"({}) and dst host {} and dst port {}",
                dest_nets_filter, self.src_ip, self.src_port
            ),
        })
    }

    pub async fn run(&self) -> Result<HashMap<IpAddr, Scanned>> {
        let interface = Interface::by_index(self.if_index)?;
        let (send_tx, send_rx) = flume::bounded::<Vec<u8>>(self.send_buffer_size);
        let (recv_tx, recv_rx) = flume::unbounded::<Vec<u8>>();
        let (result_tx, result_rx) = flume::unbounded::<Result<HashMap<IpAddr, Scanned>>>();
        let bpf = self.build_bpf()?;
        debug!("bpf filter: {}", bpf);
        let (break_handle, state, state_changed_on, time) =
            Worker::new(self.pool, interface.to_pcap()?, recv_tx, send_rx, bpf).spawn()?;
        let dest_ips = self
            .dest_nets
            .iter()
            .flat_map(|ip| ip.hosts())
            .collect::<Vec<IpAddr>>();
        let sender = Sender {
            dest_ips: dest_ips.clone(),
            dest_ports: self.dest_ports.clone(),
            src_ip: self.src_ip,
            src_port: self.src_port,
            src_mac: MacAddr::from(interface.mac.ok_or(Error::NoSourceMacAvailable)?),
            gateway_mac: MacAddr::from(interface.gateway_mac.ok_or(Error::NoGatewayMacAvailable)?),
            ttl: 64,
            progress_tx: self.send_progress_tx.clone(),
        };
        let receiver = Receiver {
            dest_ips: dest_ips.clone(),
            dest_ports: self.dest_ports.clone(),
            state: state.clone(),
            state_changed_on: state_changed_on.clone(),
            time,
            timeout: self.timeout,
            progress_tx: self.recv_progress_tx.clone(),
            result_tx,
        };

        defer! {
            break_handle.breakloop();
        }

        self.pool.spawn(move || {
            debug!("sender started");
            if let Err(e) = Self::send(send_tx, sender) {
                error!("failed to send packet data: {}", e)
            }
            debug!("sender stopped");
        });
        self.pool.spawn(move || {
            debug!("receiver started");
            if let Err(e) = Self::recv(recv_rx, receiver) {
                error!("failed to recv packet data: {}", e)
            }
            debug!("receiver stopped");
        });
        result_rx
            .into_recv_async()
            .await
            .map_err(|_| Error::ResultRecvFailed)?
    }

    fn send(send_tx: flume::Sender<Vec<u8>>, sender: Sender) -> Result<()> {
        let mut buffer = vec![0u8; Self::tcp_syn_packet_size(&sender)];
        for dest_port in sender.dest_ports {
            for dest_ip in &sender.dest_ips {
                if let Some(ref progress_tx) = sender.progress_tx {
                    progress_tx.send((*dest_ip, dest_port))?;
                }

                Self::build_ethernet(
                    &mut buffer[..14],
                    sender.src_mac,
                    sender.gateway_mac,
                    match sender.src_ip {
                        IpAddr::V4(_) => EtherTypes::Ipv4,
                        IpAddr::V6(_) => EtherTypes::Ipv6,
                    },
                )?;
                let tcp_size = Self::build_tcp(
                    &mut buffer[match sender.src_ip {
                        IpAddr::V4(_) => 34,
                        IpAddr::V6(_) => 54,
                    }..],
                    sender.src_ip,
                    *dest_ip,
                    sender.src_port,
                    dest_port,
                )?;
                match (sender.src_ip, dest_ip) {
                    (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => Self::build_ipv4(
                        &mut buffer[14..34],
                        src_ip,
                        *dest_ip,
                        (20 + tcp_size) as u16,
                        sender.ttl,
                    ),
                    (IpAddr::V4(_), IpAddr::V6(_)) => return Err(Error::IpVersionMismatch),
                    (IpAddr::V6(_), IpAddr::V4(_)) => return Err(Error::IpVersionMismatch),
                    (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => Self::build_ipv6(
                        &mut buffer[14..54],
                        src_ip,
                        *dest_ip,
                        tcp_size as u16,
                        sender.ttl,
                    ),
                }?;
                send_tx.send(buffer.clone())?;
            }
        }
        Ok(())
    }

    fn build_ethernet(
        buffer: &mut [u8],
        src: MacAddr,
        dest: MacAddr,
        ether_type: EtherType,
    ) -> Result<usize> {
        let mut packet = MutableEthernetPacket::new(buffer).ok_or(Error::InsufficientBufferSize)?;
        packet.set_source(src);
        packet.set_destination(dest);
        packet.set_ethertype(ether_type);
        Ok(EthernetPacket::packet_size(&packet.from_packet()))
    }

    fn build_ipv4(
        buffer: &mut [u8],
        src: Ipv4Addr,
        dest: Ipv4Addr,
        total_length: u16,
        ttl: u8,
    ) -> Result<usize> {
        let mut packet = MutableIpv4Packet::new(buffer).ok_or(Error::InsufficientBufferSize)?;
        packet.set_version(4);
        packet.set_header_length(5);
        // dscp omitted
        // ecn omitted
        packet.set_total_length(total_length);
        packet.set_identification(rand::random());
        packet.set_flags(Ipv4Flags::DontFragment);
        // fragment offset omitted
        packet.set_ttl(ttl);
        packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        packet.set_source(src);
        packet.set_destination(dest);
        packet.set_checksum(ipv4::checksum(&packet.to_immutable()));
        Ok(Ipv4Packet::packet_size(&packet.from_packet()))
    }

    fn build_ipv6(
        buffer: &mut [u8],
        src: Ipv6Addr,
        dest: Ipv6Addr,
        payload_length: u16,
        ttl: u8,
    ) -> Result<usize> {
        let mut packet = MutableIpv6Packet::new(buffer).ok_or(Error::InsufficientBufferSize)?;
        packet.set_version(6);
        packet.set_traffic_class(0);
        packet.set_flow_label(0);
        packet.set_payload_length(payload_length);
        packet.set_next_header(IpNextHeaderProtocols::Tcp);
        packet.set_hop_limit(ttl);
        packet.set_source(src);
        packet.set_destination(dest);
        Ok(Ipv6Packet::packet_size(&packet.from_packet()))
    }

    fn build_tcp(
        buffer: &mut [u8],
        src_ip: IpAddr,
        dest_ip: IpAddr,
        src_port: u16,
        dest_port: u16,
    ) -> Result<usize> {
        let mut packet = MutableTcpPacket::new(buffer).ok_or(Error::InsufficientBufferSize)?;
        packet.set_source(src_port);
        packet.set_destination(dest_port);
        packet.set_sequence(rand::random());
        packet.set_acknowledgement(0);
        packet.set_reserved(0);
        packet.set_flags(TcpFlags::SYN);
        packet.set_window(65535);
        packet.set_urgent_ptr(0);
        packet.set_options(&[]);
        packet.set_data_offset((TcpPacket::packet_size(&packet.from_packet()) / 4) as u8);
        packet.set_checksum(match (src_ip, dest_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => {
                tcp::ipv4_checksum(&packet.to_immutable(), &src_ip, &dest_ip)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) => return Err(Error::IpVersionMismatch),
            (IpAddr::V6(_), IpAddr::V4(_)) => return Err(Error::IpVersionMismatch),
            (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => {
                tcp::ipv6_checksum(&packet.to_immutable(), &src_ip, &dest_ip)
            }
        });
        Ok(TcpPacket::packet_size(&packet.from_packet()))
    }

    fn tcp_syn_packet_size(sender: &Sender) -> usize {
        let mut size = 14;
        size += match sender.src_ip {
            IpAddr::V4(_) => 20,
            IpAddr::V6(_) => 40,
        };
        size + 20
    }

    fn recv(recv_rx: flume::Receiver<Vec<u8>>, receiver: Receiver) -> Result<()> {
        let result = Arc::new(RwLock::new(
            receiver
                .dest_ips
                .iter()
                .map(|dest_ip| {
                    (
                        *dest_ip,
                        Scanned {
                            opened: vec![],
                            closed: vec![],
                            unknown: receiver.dest_ports.clone(),
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
        ));
        let progress_tx = receiver.progress_tx.clone();

        // wait until receiver is started
        while receiver.state.load(Ordering::Relaxed) == State::Stopped {
            rayon::yield_now();
        }

        let emit = loop {
            match result.read() {
                Ok(lock) => {
                    if lock.values().all(|scanned| scanned.unknown.is_empty()) {
                        break Ok(lock.clone());
                    }

                    match receiver.state.load(Ordering::Relaxed) {
                        State::Idle | State::Stopped => {
                            if Duration::from_millis(
                                Instant::now().duration_since(receiver.time).as_millis() as u64
                                    - receiver.state_changed_on.load(Ordering::Acquire),
                            ) >= receiver.timeout
                            {
                                break Err(Error::Timeout(lock.clone()));
                            }
                        }
                        State::Busy => {}
                    }
                }
                Err(_) => break Err(Error::RwLockPoisoned),
            }

            match recv_rx.try_recv() {
                Ok(packet) => recv_rx
                    .drain()
                    .chain(iter::once(packet))
                    .for_each(|packet| {
                        let result = result.clone();
                        let progress_tx = progress_tx.clone();
                        rayon::spawn(move || {
                            match (Self::parse_ethernet(packet, result.clone()), progress_tx) {
                                (Ok(Some((dest_ip, flags, port))), Some(progress_tx)) => {
                                    if let Err(e) = progress_tx.send((dest_ip, flags, port)) {
                                        error!("failed to send progress: {}", e);
                                    }
                                }
                                (Err(e), _) => error!("failed to parse packet: {}", e),
                                _ => {}
                            }
                        })
                    }),
                Err(TryRecvError::Empty) => {}
                Err(e) => break Err(Error::from(e)),
            }
        };

        receiver
            .result_tx
            .send(emit)
            .map_err(|_| Error::ResultSendFailed)?;
        Ok(())
    }

    fn parse_ethernet(
        packet: Vec<u8>,
        result: Arc<RwLock<HashMap<IpAddr, Scanned>>>,
    ) -> Result<Option<(IpAddr, u8, u16)>> {
        let packet = EthernetPacket::new(&packet).ok_or(Error::InvalidPacketData)?;

        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let packet = Ipv4Packet::new(packet.payload()).ok_or(Error::InvalidPacketData)?;
                let src_ip = IpAddr::V4(packet.get_source());
                Ok(Self::parse_ip_next_protocol(
                    packet.payload(),
                    packet.get_next_level_protocol(),
                    src_ip,
                    result,
                )?
                .map(|r| (src_ip, r.0, r.1)))
            }
            EtherTypes::Ipv6 => {
                let packet = Ipv6Packet::new(packet.payload()).ok_or(Error::InvalidPacketData)?;
                let src_ip = IpAddr::V6(packet.get_source());
                Ok(Self::parse_ip_next_protocol(
                    packet.payload(),
                    packet.get_next_header(),
                    src_ip,
                    result,
                )?
                .map(|r| (src_ip, r.0, r.1)))
            }
            other => Err(Error::UnsupportedEtherType(other)),
        }
    }

    fn parse_ip_next_protocol(
        packet: &[u8],
        ip_next_protocol: IpNextHeaderProtocol,
        src_ip: IpAddr,
        result: Arc<RwLock<HashMap<IpAddr, Scanned>>>,
    ) -> Result<Option<(u8, u16)>> {
        match ip_next_protocol {
            IpNextHeaderProtocols::Tcp => Self::parse_tcp(packet, src_ip, result),
            other => Err(Error::UnsupportedIpNextProtocol(other)),
        }
    }

    fn parse_tcp(
        packet: &[u8],
        src_ip: IpAddr,
        result: Arc<RwLock<HashMap<IpAddr, Scanned>>>,
    ) -> Result<Option<(u8, u16)>> {
        let packet = TcpPacket::new(packet).ok_or(Error::InvalidPacketData)?;
        let port = packet.get_source();
        let flags = packet.get_flags();
        let mut lock = result.write().map_err(|_| Error::RwLockPoisoned)?;
        let scanned = lock
            .get_mut(&src_ip)
            .ok_or(Error::NoValidSourceIp(src_ip))?;

        if !scanned.unknown.contains(&port) {
            return Ok(None);
        }

        match flags {
            CLOSED => scanned.closed.push(port),
            OPENED => scanned.opened.push(port),
            _ => return Ok(None),
        }

        scanned.unknown.retain(|p| *p != port);
        Ok(Some((flags, port)))
    }
}
