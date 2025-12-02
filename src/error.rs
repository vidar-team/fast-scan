pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("network interface not found")]
    InterfaceNotFound,

    #[error("unsupported channel type")]
    UnsupportedChannelType,

    #[error("invalid packet data")]
    InvalidPacketData,

    #[error("send progress send failed: {0}")]
    SendProgressSendFailed(#[from] flume::SendError<(std::net::IpAddr, u16)>),

    #[error("recv progress send failed: {0}")]
    RecvProgressSendFailed(#[from] flume::SendError<(u8, u16)>),

    #[error("packet send failed: {0}")]
    PacketSendFailed(#[from] flume::SendError<Vec<u8>>),

    #[error("flume recv failed: {0}")]
    FlumeRecvFailed(#[from] flume::RecvError),

    #[error("insufficient buffer size")]
    InsufficientBufferSize,

    #[error("ip version mismatch")]
    IpVersionMismatch,

    #[error("all destination ports exhausted")]
    DestinationPortsExhausted,

    #[error("all destination ips exhausted")]
    DestinationIpsExhausted,

    #[error("no valid source ip address")]
    NoValidSourceIp(std::net::IpAddr),

    #[error("no source mac address available")]
    NoSourceMacAvailable,

    #[error("no gateway mac address available")]
    NoGatewayMacAvailable,

    #[error("no interface matched")]
    NoInterfaceMatched,

    #[error("pcap failed: {0}")]
    PcapFailed(#[from] pcap::Error),

    #[error("wait tokio failed: {0}")]
    WaitTokioFailed(#[from] tokio::task::JoinError),

    #[error("timeout")]
    Timeout(std::collections::HashMap<std::net::IpAddr, crate::scan::tcp_syn::Scanned>),

    #[error("unsupported ether type: {0}")]
    UnsupportedEtherType(pnet::packet::ethernet::EtherType),

    #[error("unsupported ip next protocol: {0}")]
    UnsupportedIpNextProtocol(pnet::packet::ip::IpNextHeaderProtocol),

    #[error("invalid prefix length: {0}")]
    InvalidPrefixLength(#[from] ipnet::PrefixLenError),
}
