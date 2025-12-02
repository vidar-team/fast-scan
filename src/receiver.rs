use crate::error::{Error, Result};
use log::{debug, error};
use pnet::{
    datalink::DataLinkReceiver,
    packet::{
        FromPacket, Packet,
        arp::ArpPacket,
        ethernet::{EtherType, EtherTypes, Ethernet, EthernetPacket},
        icmp::IcmpPacket,
        icmpv6::Icmpv6Packet,
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
    },
};
use rayon::ThreadPool;
use std::{net::IpAddr, sync::Arc, time::Instant};

#[derive(Clone)]
pub struct Filter {
    pub ether_type: Vec<EtherType>,
    pub src_ip: Vec<IpAddr>,
    pub dest_ip: Vec<IpAddr>,
    pub src_port: Vec<u16>,
    pub dest_port: Vec<u16>,
    pub ip_next_protocol: Vec<IpNextHeaderProtocol>,
    pub tcp_flags: Vec<u8>,
}

pub struct EthernetReceiver<'a> {
    rx: Box<dyn DataLinkReceiver + 'static>,
    pool: &'a ThreadPool,
    data_tx: flume::Sender<Ethernet>,
    filter: Arc<Filter>,
}

impl<'a> EthernetReceiver<'a> {
    pub fn new(
        pool: &'a ThreadPool,
        rx: Box<dyn DataLinkReceiver + 'static>,
        data_tx: flume::Sender<Ethernet>,
        filter: &Filter,
    ) -> Self {
        Self {
            rx,
            pool,
            data_tx,
            filter: Arc::new(filter.clone()),
        }
    }

    pub fn spawn(mut self) {
        self.pool.spawn(move || {
            debug!("ethernet receiver started");
            while let Ok(raw) = self.rx.next()
                && !self.data_tx.is_disconnected()
            {
                let raw = raw.to_vec();
                let filter = self.filter.clone();
                let data_tx = self.data_tx.clone();
                rayon::spawn(move || {
                    if let Err(e) = Self::filter_ethernet(raw, data_tx, &filter) {
                        error!("failed to handle raw packet: {}", e);
                    }
                });
            }
            debug!("ethernet receiver stopped");
        });
    }

    fn filter_ethernet(
        packet: Vec<u8>,
        data_tx: flume::Sender<Ethernet>,
        filter: &Filter,
    ) -> Result<bool> {
        let packet = EthernetPacket::new(&packet).ok_or(Error::InvalidPacketData)?;
        let ether_type = packet.get_ethertype();

        if !Self::filter_ether_type(&ether_type, filter) {
            return Ok(false);
        }

        if !match ether_type {
            EtherTypes::Arp => Self::filter_arp(&packet, filter),
            EtherTypes::Ipv4 => Self::filter_ipv4(&packet, filter),
            EtherTypes::Ipv6 => Self::filter_ipv6(&packet, filter),
            other => Err(Error::UnsupportedEtherType(other)),
        }? {
            return Ok(false);
        }

        data_tx
            .send(packet.from_packet())
            .map_err(|e| Error::DataSendFailed(e))?;

        Ok(true)
    }

    fn filter_arp(packet: &EthernetPacket<'_>, filter: &Filter) -> Result<bool> {
        let packet = ArpPacket::new(packet.payload()).ok_or(Error::InvalidPacketData)?;

        if !Self::filter_host(
            IpAddr::V4(packet.get_sender_proto_addr()),
            IpAddr::V4(packet.get_target_proto_addr()),
            filter,
        ) {
            return Ok(false);
        }

        Ok(true)
    }

    fn filter_ipv4(packet: &EthernetPacket<'_>, filter: &Filter) -> Result<bool> {
        let packet = Ipv4Packet::new(packet.payload()).ok_or(Error::InvalidPacketData)?;

        if !Self::filter_host(
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            filter,
        ) {
            return Ok(false);
        }

        if !Self::filter_ip_next_protocol(
            packet.get_next_level_protocol(),
            packet.payload(),
            filter,
        )? {
            return Ok(false);
        }

        Ok(true)
    }

    fn filter_ipv6(packet: &EthernetPacket<'_>, filter: &Filter) -> Result<bool> {
        let packet = Ipv6Packet::new(packet.payload()).ok_or(Error::InvalidPacketData)?;

        if !Self::filter_host(
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            filter,
        ) {
            return Ok(false);
        }

        if !Self::filter_ip_next_protocol(packet.get_next_header(), packet.payload(), filter)? {
            return Ok(false);
        }

        Ok(true)
    }

    fn filter_ip_next_protocol(
        ip_next_protocol: IpNextHeaderProtocol,
        packet: &[u8],
        filter: &Filter,
    ) -> Result<bool> {
        if !filter.ip_next_protocol.is_empty()
            && !filter.ip_next_protocol.contains(&ip_next_protocol)
        {
            return Ok(false);
        }

        match ip_next_protocol {
            IpNextHeaderProtocols::Tcp => Self::filter_tcp(packet, filter),
            IpNextHeaderProtocols::Udp => Self::filter_udp(packet, filter),
            // IpNextHeaderProtocols::Icmp => Self::filter_icmp(packet, filter),
            // IpNextHeaderProtocols::Icmpv6 => Self::filter_icmpv6(packet, filter),
            other => Err(Error::UnsupportedIpNextProtocol(other)),
        }
    }

    fn filter_tcp(packet: &[u8], filter: &Filter) -> Result<bool> {
        let packet = TcpPacket::new(packet).ok_or(Error::InvalidPacketData)?;

        if !Self::filter_port(packet.get_source(), packet.get_destination(), filter) {
            return Ok(false);
        }

        if !Self::filter_tcp_flags(packet.get_flags(), filter) {
            return Ok(false);
        }

        Ok(true)
    }

    fn filter_udp(packet: &[u8], filter: &Filter) -> Result<bool> {
        let packet = UdpPacket::new(packet).ok_or(Error::InvalidPacketData)?;

        if !Self::filter_port(packet.get_source(), packet.get_destination(), filter) {
            return Ok(false);
        }

        Ok(true)
    }

    // fn filter_icmp(packet: &[u8], _filter: &Filter) -> Result<bool> {
    //     let _packet = IcmpPacket::new(packet).ok_or(Error::InvalidPacketData)?;
    //     todo!();
    //     Ok(true)
    // }

    // fn filter_icmpv6(packet: &[u8], _filter: &Filter) -> Result<bool> {
    //     let _packet = Icmpv6Packet::new(packet).ok_or(Error::InvalidPacketData)?;
    //     todo!();
    //     Ok(true)
    // }

    fn filter_ether_type(ether_type: &EtherType, filter: &Filter) -> bool {
        filter.ether_type.is_empty() || filter.ether_type.contains(&ether_type)
    }

    fn filter_host(src: IpAddr, dest: IpAddr, filter: &Filter) -> bool {
        (filter.src_ip.is_empty() && filter.dest_ip.is_empty())
            || filter.src_ip.contains(&src)
            || filter.dest_ip.contains(&dest)
    }

    fn filter_port(src: u16, dst: u16, filter: &Filter) -> bool {
        (filter.src_port.is_empty() && filter.dest_port.is_empty())
            || filter.src_port.contains(&src)
            || filter.dest_port.contains(&dst)
    }

    fn filter_tcp_flags(flags: u8, filter: &Filter) -> bool {
        filter.tcp_flags.is_empty() || filter.tcp_flags.iter().any(|f| flags & f == *f)
    }
}
