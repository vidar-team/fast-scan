use crate::{Error, Result};
use pcap::Device;
use pnet::datalink;
use std::net::IpAddr;

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub friendly_name: Option<String>,
    pub index: u32,
    pub ips: Vec<IpAddr>,
    pub mac: Option<[u8; 6]>,
    pub gateway_mac: Option<[u8; 6]>,
}

impl Interface {
    pub fn list() -> Result<Vec<Self>> {
        let front = datalink::interfaces();
        let back = Device::list()?;
        let mid = netdev::get_interfaces();
        let mut result = Vec::new();

        for back in back {
            let front = match front.iter().find(|f| f.name == back.name) {
                Some(front) => front,
                None => continue,
            };
            let mid = mid
                .iter()
                .find(|m| m.index == front.index)
                .ok_or(Error::NoInterfaceMatched)?;

            result.push(Self {
                name: back.name,
                friendly_name: mid.friendly_name.clone(),
                index: front.index,
                ips: back.addresses.iter().map(|address| address.addr).collect(),
                mac: front.mac.map(|mac| mac.octets()),
                gateway_mac: mid
                    .gateway
                    .as_ref()
                    .map(|gateway| gateway.mac_addr.octets()),
            });
        }
        Ok(result)
    }

    pub fn pcap_by_index(index: u32) -> Result<Device> {
        let front = datalink::interfaces();
        let back = Device::list()?;

        back.into_iter()
            .find(|b| front.iter().any(|f| f.name == b.name && f.index == index))
            .ok_or(Error::NoInterfaceMatched)
    }

    pub fn by_index(index: u32) -> Result<Self> {
        let front = datalink::interfaces()
            .into_iter()
            .find(|f| f.index == index)
            .ok_or(Error::NoInterfaceMatched)?;
        let back = Device::list()?
            .into_iter()
            .find(|b| front.name == b.name)
            .ok_or(Error::NoInterfaceMatched)?;
        let mid = netdev::get_interfaces()
            .into_iter()
            .find(|m| m.index == front.index)
            .ok_or(Error::NoInterfaceMatched)?;

        Ok(Self {
            name: back.name,
            friendly_name: mid.friendly_name.clone(),
            index: front.index,
            ips: back.addresses.iter().map(|address| address.addr).collect(),
            mac: front.mac.map(|mac| mac.octets()),
            gateway_mac: mid
                .gateway
                .as_ref()
                .map(|gateway| gateway.mac_addr.octets()),
        })
    }

    pub fn to_pcap(&self) -> Result<Device> {
        Self::pcap_by_index(self.index)
    }
}
