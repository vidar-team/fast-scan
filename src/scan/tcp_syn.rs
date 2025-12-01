use crate::{
    error::{Error, Result},
    receiver::{EthernetReceiver, Filter},
    sender::{EthernetSender, SendConfig, TcpSyn},
};
use log::debug;
use netdev::interface;
use pnet::{
    datalink::{self, Channel, Config as DataLinkConfig},
    packet::{
        Packet,
        ethernet::{EtherTypes, Ethernet},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::{TcpFlags, TcpPacket},
    },
    util::MacAddr,
};
use rayon::ThreadPool;
use std::{collections::HashMap, net::IpAddr, time::Duration};
use tokio::{select, time};

const CLOSED: u8 = TcpFlags::ACK | TcpFlags::RST;
const OPENED: u8 = TcpFlags::ACK | TcpFlags::SYN;

pub struct Scanner<'a> {
    pub pool: &'a ThreadPool,
    pub if_index: u32,
    pub dest_ips: Vec<IpAddr>,
    pub dest_ports: Vec<u16>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub wait_after_send: Duration,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct ScanResult {
    pub opened: Vec<u16>,
    pub closed: Vec<u16>,
    pub unknown: Vec<u16>,
}

impl<'a> Scanner<'a> {
    pub async fn run(&self) -> Result<HashMap<IpAddr, ScanResult>> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|interface| interface.index == self.if_index)
            .ok_or(Error::InterfaceNotFound)?;
        let gateway = interface::get_interfaces()
            .into_iter()
            .find(|interface| interface.index == self.if_index)
            .and_then(|interface| interface.gateway)
            .ok_or(Error::NoGatewayAvailable)?;
        let (data_tx, data_rx) = flume::unbounded();
        let filter = Filter {
            ether_type: vec![EtherTypes::Ipv4, EtherTypes::Ipv6],
            src_ip: self.dest_ips.clone(),
            dest_ip: vec![self.src_ip],
            src_port: vec![],
            dest_port: vec![self.src_port],
            ip_next_protocol: vec![IpNextHeaderProtocols::Tcp],
            tcp_flags: vec![CLOSED, OPENED],
        };
        let config = SendConfig::TcpSyn(TcpSyn {
            dest_ips: self.dest_ips.clone(),
            dest_ports: self.dest_ports.clone(),
            src_ip: self.src_ip,
            src_port: self.src_port,
            src_mac: interface.mac.ok_or(Error::NoSourceMacAddressAvailable)?,
            gateway_mac: MacAddr::from(gateway.mac_addr.octets()),
            wait_after_send: self.wait_after_send,
            ttl: 64,
        });
        let mut results = self
            .dest_ips
            .iter()
            .map(|dest_ip| {
                (
                    *dest_ip,
                    ScanResult {
                        opened: vec![],
                        closed: vec![],
                        unknown: self.dest_ports.clone(),
                    },
                )
            })
            .collect();

        match datalink::channel(&interface, DataLinkConfig::default())
            .map_err(|e| Error::ChannelCreationFailed(e))?
        {
            Channel::Ethernet(tx, rx) => {
                EthernetReceiver::new(&self.pool, rx, data_tx, &filter).spawn();
                EthernetSender::new(&self.pool, tx, config)?.spawn();

                loop {
                    select! {
                        packet = data_rx.recv_async() => {
                            let packet = packet.map_err(|e| Error::DataRecvFailed(e))?;
                            if Self::parse_ethernet(packet, &mut results)?
                                && results.values().all(|result| result.unknown.is_empty())
                            {
                                break Ok(results);
                            }
                        }
                        _ = time::sleep(self.timeout) => break Err(Error::Timeout(results)),
                    }
                }
            }
            _ => return Err(Error::UnsupportedChannelType),
        }
    }

    fn parse_ethernet(packet: Ethernet, results: &mut HashMap<IpAddr, ScanResult>) -> Result<bool> {
        match packet.ethertype {
            EtherTypes::Ipv4 => {
                let packet = Ipv4Packet::new(&packet.payload).ok_or(Error::InvalidPacketData)?;
                let src_ip = IpAddr::V4(packet.get_source());
                Self::parse_ip_next_protocol(
                    packet.get_next_level_protocol(),
                    packet.payload(),
                    results
                        .get_mut(&src_ip)
                        .ok_or(Error::NoValidSourceIpAddress(src_ip))?,
                )
            }
            EtherTypes::Ipv6 => {
                let packet = Ipv6Packet::new(&packet.payload).ok_or(Error::InvalidPacketData)?;
                let src_ip = IpAddr::V6(packet.get_source());
                Self::parse_ip_next_protocol(
                    packet.get_next_header(),
                    packet.payload(),
                    results
                        .get_mut(&src_ip)
                        .ok_or(Error::NoValidSourceIpAddress(src_ip))?,
                )
            }
            other => Err(Error::UnsupportedEtherType(other)),
        }
    }

    fn parse_ip_next_protocol(
        ip_next_protocol: IpNextHeaderProtocol,
        packet: &[u8],
        result: &mut ScanResult,
    ) -> Result<bool> {
        match ip_next_protocol {
            IpNextHeaderProtocols::Tcp => Self::parse_tcp(packet, result),
            other => Err(Error::UnsupportedIpNextProtocol(other)),
        }
    }

    fn parse_tcp(packet: &[u8], result: &mut ScanResult) -> Result<bool> {
        let packet = TcpPacket::new(packet).ok_or(Error::InvalidPacketData)?;
        let port = packet.get_source();
        let flags = packet.get_flags();

        if !result.unknown.contains(&port) {
            return Ok(false);
        }

        match flags {
            CLOSED => result.closed.push(port),
            OPENED => result.opened.push(port),
            _ => return Ok(false),
        }

        result.unknown.retain(|&p| p != port);
        Ok(true)
    }
}
