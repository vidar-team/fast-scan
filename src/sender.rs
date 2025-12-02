use crate::error::{Error, Result};
use log::{debug, error};
use num_integer::Integer;
use pnet::{
    datalink::DataLinkSender,
    packet::{
        FromPacket,
        ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
        ipv6::MutableIpv6Packet,
        tcp::{self, MutableTcpPacket, TcpFlags, TcpOption, TcpPacket},
    },
    util::MacAddr,
};
use rayon::ThreadPool;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{self, Duration},
};

pub enum SendConfig {
    TcpSyn(TcpSyn),
}

pub struct TcpSyn {
    pub dest_ips: Vec<IpAddr>,
    pub dest_ports: Vec<u16>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub src_mac: MacAddr,
    pub gateway_mac: MacAddr,
    pub wait_after_send: Option<Duration>,
    pub ttl: u8,
}

pub struct EthernetSender<'a> {
    tx: Box<dyn DataLinkSender + 'static>,
    pool: &'a ThreadPool,
    scan_config: SendConfig,
    counter: usize,
    progress_tx: Option<flume::Sender<(usize, IpAddr, u16)>>,
    stopped: Arc<AtomicBool>,
}

impl<'a> EthernetSender<'a> {
    pub fn new(
        pool: &'a ThreadPool,
        tx: Box<dyn DataLinkSender + 'static>,
        progress_tx: Option<flume::Sender<(usize, IpAddr, u16)>>,
        scan_config: SendConfig,
    ) -> Result<Self> {
        if let Some(e) = match &scan_config {
            SendConfig::TcpSyn(config) => config
                .dest_ips
                .iter()
                .any(|dest_ip| match (config.src_ip, dest_ip) {
                    (IpAddr::V4(_), IpAddr::V4(_)) => false,
                    (IpAddr::V4(_), IpAddr::V6(_)) => true,
                    (IpAddr::V6(_), IpAddr::V4(_)) => true,
                    (IpAddr::V6(_), IpAddr::V6(_)) => false,
                })
                .then_some(Error::IpVersionMismatch),
        } {
            return Err(e);
        }

        Ok(Self {
            tx,
            pool,
            scan_config,
            progress_tx,
            counter: 0,
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn spawn(mut self) -> Arc<AtomicBool> {
        let stopped = self.stopped.clone();
        self.pool.spawn(move || {
            debug!("ethernet sender started");
            if let Err(e) = Self::send(
                self.tx,
                &mut self.scan_config,
                &mut self.counter,
                self.progress_tx,
            ) {
                error!("failed to send packet: {}", e);
            }
            self.stopped.store(true, Ordering::Relaxed);
            debug!("ethernet sender stopped");
        });
        stopped
    }

    fn send(
        mut tx: Box<dyn DataLinkSender + 'static>,
        scan_config: &mut SendConfig,
        counter: &mut usize,
        progress_tx: Option<flume::Sender<(usize, IpAddr, u16)>>,
    ) -> Result<()> {
        let (num_packets, packet_size, wait_after_send, mut func) = match scan_config {
            SendConfig::TcpSyn(config) => (
                config.dest_ports.len() * config.dest_ips.len(),
                Self::tcp_syn_packet_size(config),
                config.wait_after_send,
                move |buffer: &mut [u8]| {
                    if let Err(e) =
                        Self::build_tcp_syn_packet(buffer, config, counter, progress_tx.clone())
                    {
                        error!("failed to build tcp syn packet: {}", e);
                    }
                },
            ),
        };
        for _ in 0..num_packets {
            if let Some(wait_after_send) = wait_after_send {
                thread::sleep(wait_after_send);
            }
            tx.build_and_send(1, packet_size, &mut func)
                .ok_or(Error::InsufficientBufferSize)??;
        }
        Ok(())
    }

    fn build_tcp_syn_packet(
        buffer: &mut [u8],
        config: &mut TcpSyn,
        counter: &mut usize,
        progress_tx: Option<flume::Sender<(usize, IpAddr, u16)>>,
    ) -> Result<()> {
        let (port_index, ip_index) = counter.div_rem(&config.dest_ips.len());
        *counter += 1;
        let dest_ip = *config
            .dest_ips
            .get(ip_index)
            .ok_or(Error::DestinationIpsExhausted)?;
        let dest_port = *config
            .dest_ports
            .get(port_index)
            .ok_or(Error::DestinationPortsExhausted)?;

        if let Some(progress_tx) = progress_tx {
            progress_tx
                .send((*counter, dest_ip, dest_port))
                .map_err(|e| Error::ProgressSendFailed(e))?;
        }

        Self::build_ethernet(
            &mut buffer[..14],
            config.src_mac,
            config.gateway_mac,
            match config.src_ip {
                IpAddr::V4(_) => EtherTypes::Ipv4,
                IpAddr::V6(_) => EtherTypes::Ipv6,
            },
        )?;
        let tcp_size = Self::build_tcp(
            &mut buffer[match config.src_ip {
                IpAddr::V4(_) => 34,
                IpAddr::V6(_) => 54,
            }..],
            config.src_ip,
            dest_ip,
            config.src_port,
            dest_port,
            65535,
            TcpFlags::SYN,
            &[],
            0,
            0,
        )?;
        match (config.src_ip, dest_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dest_ip)) => Self::build_ipv4(
                &mut buffer[14..34],
                src_ip,
                dest_ip,
                (20 + tcp_size) as u16,
                config.ttl,
                IpNextHeaderProtocols::Tcp,
            ),
            (IpAddr::V4(_), IpAddr::V6(_)) => return Err(Error::IpVersionMismatch),
            (IpAddr::V6(_), IpAddr::V4(_)) => return Err(Error::IpVersionMismatch),
            (IpAddr::V6(src_ip), IpAddr::V6(dest_ip)) => Self::build_ipv6(
                &mut buffer[14..54],
                src_ip,
                dest_ip,
                (40 + tcp_size) as u16,
                config.ttl,
                IpNextHeaderProtocols::Tcp,
            ),
        }?;
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

    fn build_ipv6(
        buffer: &mut [u8],
        src: Ipv6Addr,
        dest: Ipv6Addr,
        total_length: u16,
        ttl: u8,
        next_protocol: IpNextHeaderProtocol,
    ) -> Result<usize> {
        let packet = MutableIpv6Packet::new(buffer).ok_or(Error::InsufficientBufferSize)?;
        todo!()
    }

    fn build_tcp(
        buffer: &mut [u8],
        src_ip: IpAddr,
        dest_ip: IpAddr,
        src_port: u16,
        dest_port: u16,
        window: u16,
        flags: u8,
        options: &[TcpOption],
        urgent: u16,
        acknowledgement: u32,
    ) -> Result<usize> {
        let mut packet = MutableTcpPacket::new(buffer).ok_or(Error::InsufficientBufferSize)?;
        packet.set_source(src_port);
        packet.set_destination(dest_port);
        packet.set_sequence(rand::random());
        packet.set_acknowledgement(acknowledgement);
        packet.set_reserved(0);
        packet.set_flags(flags);
        packet.set_window(window);
        packet.set_urgent_ptr(urgent);
        packet.set_options(options);
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

    fn tcp_syn_packet_size(config: &TcpSyn) -> usize {
        let mut size = 14;
        size += match config.src_ip {
            IpAddr::V4(_) => 20,
            IpAddr::V6(_) => 40,
        };
        size + 20
    }
}
