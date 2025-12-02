use crate::{
    error::{Error, Result},
    interface::Interface,
    worker::{State, Worker},
};
use ipnet::IpNet;
use log::error;
use pnet::{
    packet::{
        FromPacket, Packet,
        ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
        ipv6::Ipv6Packet,
        tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket},
    },
    util::MacAddr,
};
use rayon::ThreadPool;
use scopeguard::defer;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{select, time};

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
    pub recv_progress_tx: Option<flume::Sender<(u8, u16)>>,
    pub send_progress_tx: Option<flume::Sender<(IpAddr, u16)>>,
}

#[derive(Debug)]
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

impl<'a> Scanner<'a> {
    pub fn build_bpf(&self) -> Result<String> {
        let dest_nets_filter = self
            .dest_nets
            .iter()
            .map(|net| format!("src net {}", net))
            .collect::<Vec<_>>()
            .join(" or ");

        Ok(format!(
            "{} and dst host {} and dst port {} and tcp[tcpflags] & tcp-ack != 0",
            dest_nets_filter, self.src_ip, self.src_port
        ))
    }

    pub async fn run(&self) -> Result<HashMap<IpAddr, Scanned>> {
        let interface = Interface::by_index(self.if_index)?;
        let (send_tx, send_rx) = flume::unbounded::<Vec<u8>>();
        let (recv_tx, recv_rx) = flume::unbounded::<Vec<u8>>();
        let (break_handle, state) = Worker::new(
            self.pool,
            interface.to_pcap()?,
            recv_tx,
            send_rx,
            self.build_bpf()?,
        )
        .spawn()?;
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

        defer! {
            break_handle.breakloop();
        }

        self.pool.spawn(move || {
            if let Err(e) = Self::send(send_tx, sender) {
                error!("failed to send packet data: {}", e)
            }
        });
        self.recv(
            recv_rx,
            self.recv_progress_tx.clone(),
            &dest_ips,
            state.clone(),
        )
        .await
    }

    fn send(send_tx: flume::Sender<Vec<u8>>, sender: Sender) -> Result<()> {
        let mut buffer = vec![0u8; Self::tcp_syn_packet_size(&sender)];
        for dest_port in &sender.dest_ports {
            for dest_ip in &sender.dest_ips {
                if let Some(progress_tx) = &sender.progress_tx {
                    progress_tx.send((*dest_ip, *dest_port))?;
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
                    *dest_port,
                )?;
                match (sender.src_ip, dest_ip) {
                    (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => Self::build_ipv4(
                        &mut buffer[14..34],
                        src_ip,
                        *dest_ip,
                        (20 + tcp_size) as u16,
                        sender.ttl,
                        IpNextHeaderProtocols::Tcp,
                    ),
                    (IpAddr::V4(_), IpAddr::V6(_)) => return Err(Error::IpVersionMismatch),
                    (IpAddr::V6(_), IpAddr::V4(_)) => return Err(Error::IpVersionMismatch),
                    // (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => Self::build_ipv6(
                    //     &mut buffer[14..54],
                    //     src_ip,
                    //     *dest_ip,
                    //     (40 + tcp_size) as u16,
                    //     sender.ttl,
                    //     IpNextHeaderProtocols::Tcp,
                    // ),
                    (IpAddr::V6(_), IpAddr::V6(_)) => todo!(),
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
        next_protocol: IpNextHeaderProtocol,
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
        packet.set_next_level_protocol(next_protocol);
        packet.set_source(src);
        packet.set_destination(dest);
        packet.set_checksum(ipv4::checksum(&packet.to_immutable()));
        Ok(Ipv4Packet::packet_size(&packet.from_packet()))
    }

    // fn build_ipv6(
    //     buffer: &mut [u8],
    //     src: Ipv6Addr,
    //     dest: Ipv6Addr,
    //     total_length: u16,
    //     ttl: u8,
    //     next_protocol: IpNextHeaderProtocol,
    // ) -> Result<usize> {
    //     let packet = MutableIpv6Packet::new(buffer).ok_or(Error::InsufficientBufferSize)?;
    //     todo!()
    // }

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

    async fn recv(
        &self,
        recv_rx: flume::Receiver<Vec<u8>>,
        recv_progress_tx: Option<flume::Sender<(u8, u16)>>,
        dest_ips: &[IpAddr],
        state: Arc<AtomicU32>,
    ) -> Result<HashMap<IpAddr, Scanned>> {
        let mut results = dest_ips
            .iter()
            .map(|dest_ip| {
                (
                    *dest_ip,
                    Scanned {
                        opened: vec![],
                        closed: vec![],
                        unknown: self.dest_ports.clone(),
                    },
                )
            })
            .collect();

        loop {
            select! {
                packet = recv_rx.recv_async() => {
                    let packet = packet?;
                    if let Some((flags, port)) = Self::parse_ethernet(packet, &mut results)? {
                        if let Some(progress_tx) = recv_progress_tx.as_ref() {
                            progress_tx.send((flags, port))?;
                        }
                        if results.values().all(|result| result.unknown.is_empty()) {
                            break Ok(results);
                        }
                    }
                }
                _ = time::sleep(self.timeout) => if state.load(Ordering::Relaxed) == State::Idle as u32 {
                    break Err(Error::Timeout(results));
                }
            }
        }
    }

    fn parse_ethernet(
        packet: Vec<u8>,
        results: &mut HashMap<IpAddr, Scanned>,
    ) -> Result<Option<(u8, u16)>> {
        let packet = EthernetPacket::new(&packet).ok_or(Error::InvalidPacketData)?;

        match packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let packet = Ipv4Packet::new(packet.payload()).ok_or(Error::InvalidPacketData)?;
                let src_ip = IpAddr::V4(packet.get_source());
                Self::parse_ip_next_protocol(
                    packet.get_next_level_protocol(),
                    packet.payload(),
                    results
                        .get_mut(&src_ip)
                        .ok_or(Error::NoValidSourceIp(src_ip))?,
                )
            }
            EtherTypes::Ipv6 => {
                let packet = Ipv6Packet::new(packet.payload()).ok_or(Error::InvalidPacketData)?;
                let src_ip = IpAddr::V6(packet.get_source());
                Self::parse_ip_next_protocol(
                    packet.get_next_header(),
                    packet.payload(),
                    results
                        .get_mut(&src_ip)
                        .ok_or(Error::NoValidSourceIp(src_ip))?,
                )
            }
            other => Err(Error::UnsupportedEtherType(other)),
        }
    }

    fn parse_ip_next_protocol(
        ip_next_protocol: IpNextHeaderProtocol,
        packet: &[u8],
        scanned: &mut Scanned,
    ) -> Result<Option<(u8, u16)>> {
        match ip_next_protocol {
            IpNextHeaderProtocols::Tcp => Self::parse_tcp(packet, scanned),
            other => Err(Error::UnsupportedIpNextProtocol(other)),
        }
    }

    fn parse_tcp(packet: &[u8], scanned: &mut Scanned) -> Result<Option<(u8, u16)>> {
        let packet = TcpPacket::new(packet).ok_or(Error::InvalidPacketData)?;
        let port = packet.get_source();
        let flags = packet.get_flags();

        if !scanned.unknown.contains(&port) {
            return Ok(None);
        }

        match flags {
            CLOSED => scanned.closed.push(port),
            OPENED => scanned.opened.push(port),
            _ => return Ok(None),
        }

        scanned.unknown.retain(|&p| p != port);
        Ok(Some((flags, port)))
    }
}
