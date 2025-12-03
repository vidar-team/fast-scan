use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;
use std::{collections::HashSet, net::IpAddr};

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

#[derive(Args)]
pub struct TcpSynArg {
    #[arg(long)]
    pub src_ip: Option<IpAddr>,

    #[arg(long, required = true, value_delimiter = ',')]
    pub dest_nets: Vec<IpNet>,

    // use std::vec::Vec<u16> here
    // https://github.com/clap-rs/clap/issues/4679
    #[arg(long, required = true, value_parser = parse_range)]
    pub dest_ports: std::vec::Vec<u16>,

    #[arg(short, long, default_value_t = default_if_index())]
    pub if_index: u32,

    #[arg(short, long, default_value_t = 12)]
    pub thread: usize,

    #[arg(short, long, default_value_t = 30000)]
    pub send_buffer_size: usize,
}

fn parse_range(s: &str) -> Result<Vec<u16>> {
    let mut result = HashSet::new();

    for part in s.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start = start.trim().parse::<u16>()?;
            let end = end.trim().parse::<u16>()?;

            if start > end {
                bail!("bad range: {}", part);
            }

            result.extend(start..=end);
        } else {
            result.insert(part.trim().parse::<u16>()?);
        }
    }

    Ok(result.into_iter().collect())
}

fn default_if_index() -> u32 {
    netdev::get_default_interface()
        .expect("no default interface provided")
        .index
}
