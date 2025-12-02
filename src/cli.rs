use clap::{Parser, Subcommand};
use std::net::IpAddr;

#[derive(Parser)]
pub struct Arg {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    TcpSyn(TcpSynArg),
    ListInterfaces,
}

#[derive(Parser)]
pub struct TcpSynArg {
    #[arg(long)]
    pub src_ip: Option<IpAddr>,

    #[arg(long, required = true)]
    pub dest_ips: Vec<IpAddr>,

    #[arg(long, required = true)]
    pub dest_ports: Vec<u16>,

    #[arg(short, long)]
    pub if_index: Option<u32>,

    #[arg(short, long, default_value_t = 5)]
    pub thread: usize,
}
