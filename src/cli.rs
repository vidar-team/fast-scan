use clap::Parser;
use std::net::IpAddr;

#[derive(Parser)]
pub struct Arg {
    #[arg(long)]
    pub src_ip: IpAddr,

    #[arg(long, required = true)]
    pub dest_ips: Vec<IpAddr>,

    #[arg(long, required = true)]
    pub dest_ports: Vec<u16>,

    #[arg(short, long)]
    pub if_index: Option<u32>,

    #[arg(short, long, default_value_t = 5)]
    pub thread: usize,
}
