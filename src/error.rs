pub type Result<T> = std::result::Result<T, Error>;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid packet data")]
    InvalidPacketData,

    #[error("send progress send failed: {0}")]
    SendProgressSendFailed(#[from] flume::SendError<(std::net::IpAddr, u16)>),

    #[error("recv progress send failed: {0}")]
    RecvProgressSendFailed(#[from] flume::SendError<(std::net::IpAddr, u8, u16)>),

    #[error("result send failed")]
    ResultSendFailed,

    #[error("result recv failed")]
    ResultRecvFailed,

    #[error("packet send failed: {0}")]
    PacketSendFailed(#[from] flume::SendError<Vec<u8>>),

    #[error("flume try recv failed: {0}")]
    FlumeTryRecvFailed(#[from] flume::TryRecvError),

    #[error("flume recv failed: {0}")]
    FlumeRecvFailed(#[from] flume::RecvError),

    #[error("insufficient buffer size")]
    InsufficientBufferSize,

    #[error("ip version mismatch")]
    IpVersionMismatch,

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

    #[error("all destination ports exhausted")]
    DestinationPortsExhausted,

    #[error("all destination ips exhausted")]
    DestinationIpsExhausted,

    #[error("timeout")]
    Timeout(std::collections::HashMap<std::net::IpAddr, crate::scan::tcp_syn::Scanned>),

    #[error("worker aborted")]
    WorkerAbortedWith(std::collections::HashMap<std::net::IpAddr, crate::scan::tcp_syn::Scanned>),

    #[error("worker aborted")]
    WorkerAborted,

    #[error("unsupported ether type: {0}")]
    UnsupportedEtherType(pnet::packet::ethernet::EtherType),

    #[error("unsupported ip next protocol: {0}")]
    UnsupportedIpNextProtocol(pnet::packet::ip::IpNextHeaderProtocol),

    #[error("invalid prefix length: {0}")]
    InvalidPrefixLength(#[from] ipnet::PrefixLenError),

    #[error("rwlock poisoned")]
    RwLockPoisoned,
}
