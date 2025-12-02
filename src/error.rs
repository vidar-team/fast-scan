pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network interface not found")]
    InterfaceNotFound,

    #[error("failed to create data link channel: {0}")]
    ChannelCreationFailed(#[from] std::io::Error),

    #[error("unsupported channel type")]
    UnsupportedChannelType,

    #[error("invalid packet data")]
    InvalidPacketData,

    #[error("data send failed: {0}")]
    DataSendFailed(#[from] flume::SendError<pnet::packet::ethernet::Ethernet>),

    #[error("progress send failed: {0}")]
    ProgressSendFailed(#[from] flume::SendError<(usize, std::net::IpAddr, u16)>),

    #[error("data recv failed: {0}")]
    DataRecvFailed(#[from] flume::RecvError),

    #[error("unsupported ether type: {0}")]
    UnsupportedEtherType(pnet::packet::ethernet::EtherType),

    #[error("unsupported ip next protocol: {0}")]
    UnsupportedIpNextProtocol(pnet::packet::ip::IpNextHeaderProtocol),

    #[error("insufficient buffer size")]
    InsufficientBufferSize,

    #[error("ip version mismatch")]
    IpVersionMismatch,

    #[error("all destination ports exhausted")]
    DestinationPortsExhausted,

    #[error("all destination ips exhausted")]
    DestinationIpsExhausted,

    #[error("no valid source ip address")]
    NoValidSourceIpAddress(std::net::IpAddr),

    #[error("no source mac address available")]
    NoSourceMacAddressAvailable,

    #[error("no gateway available")]
    NoGatewayAvailable,

    #[error("timeout")]
    Timeout(std::collections::HashMap<std::net::IpAddr, crate::scan::tcp_syn::ScanResult>),
}
