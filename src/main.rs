mod cli;

use crate::cli::{Arg, Command, TcpSynArg};
use anyhow::{Result, anyhow};
use clap::Parser;
use fast_scan::{
    Error,
    scan::tcp_syn::{self},
};
use indicatif::ProgressBar;
use log::{LevelFilter, error, info};
use rayon::ThreadPoolBuilder;
use std::{net::IpAddr, time::Duration};
use tokio::time::Instant;

struct Progress {
    progress_rx: flume::Receiver<(usize, IpAddr, u16)>,
    progress: ProgressBar,
}

impl Progress {
    fn new(total: usize) -> (Self, flume::Sender<(usize, IpAddr, u16)>) {
        let (progress_tx, progress_rx) = flume::unbounded();
        let progress = ProgressBar::new(total as u64);
        (
            Self {
                progress_rx,
                progress,
            },
            progress_tx,
        )
    }

    async fn run(self) {
        while let Ok((_index, _ip, _port)) = self.progress_rx.recv_async().await {
            self.progress.inc(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    flexi_logger::Logger::with(LevelFilter::Debug).start()?;
    let arg = Arg::try_parse()?;

    match arg.command {
        Command::TcpSyn(arg) => tcp_syn(arg).await,
        Command::ListInterfaces => list_interfaces().await,
    }
}

async fn list_interfaces() -> Result<()> {
    netdev::get_interfaces()
        .into_iter()
        .for_each(|interface| match interface.gateway {
            Some(gateway) => info!(
                "index: {}, name: {}, mac: {}, gateway_mac: {}, ipv4: {:?}, ipv6: {:?}, gateway_ipv4: {:?}, gateway_ipv6: {:?}",
                interface.index,
                interface.description.unwrap_or(interface.name),
                interface.mac_addr.map_or("<unknown>".to_string(), |mac|mac.to_string()),
                gateway.mac_addr,
                interface.ipv4,
                interface.ipv6,
                gateway.ipv4,
                gateway.ipv6,
            ),
            None => info!(
                "index: {}, name: {}, mac: {}, ipv4: {:?}, ipv6: {:?}",
                interface.index,
                interface.description.unwrap_or(interface.name),
                interface.mac_addr.map_or("<unknown>".to_string(), |mac|mac.to_string()),
                interface.ipv4,
                interface.ipv6
            ),
        });
    Ok(())
}

async fn tcp_syn(arg: TcpSynArg) -> Result<()> {
    let if_index = match arg.if_index {
        Some(if_index) => if_index,
        None => {
            netdev::get_default_interface()
                .map_err(|e| anyhow!(e))?
                .index
        }
    };

    let pool = ThreadPoolBuilder::new().num_threads(arg.thread).build()?;

    let src_ip = match arg.src_ip {
        Some(ip) => ip,
        None => netdev::get_default_interface()
            .map_err(|e| anyhow!(e))?
            .ip_addrs()
            .into_iter()
            .next()
            .ok_or(anyhow!("no default ipv4 address"))?,
    };
    let dest_ips = arg
        .dest_ips
        .iter()
        .map(|ip| ip.hosts())
        .flatten()
        .collect::<Vec<IpAddr>>();
    let dest_ports = arg.dest_ports;
    let count = dest_ips.len() * dest_ports.len();

    info!(
        "start tcp syn scan, if_index: {}, src_ip: {}, dest_ips: {:?}, dest_ports: {:?}",
        if_index, src_ip, dest_ips, dest_ports
    );

    let (progress, progress_tx) = Progress::new(count);

    let scanner = tcp_syn::Scanner {
        pool: &pool,
        if_index,
        dest_ips,
        dest_ports,
        src_ip,
        src_port: rand::random(),
        timeout: Duration::from_secs(2),
        wait_after_send: Some(Duration::from_nanos(1)),
        progress_tx: Some(progress_tx),
    };

    let start = Instant::now();
    tokio::spawn(progress.run());
    let results = scanner.run().await;
    let duration = Instant::now() - start;
    info!(
        "scan completed in {:.2} secs, {:.2} ports/sec",
        duration.as_secs_f64(),
        count as f64 / duration.as_secs_f64()
    );

    match results {
        Ok(results) | Err(Error::Timeout(results)) => {
            for (ip, result) in results
                .iter()
                .filter(|(_, result)| !result.opened.is_empty())
            {
                info!(
                    "{}: opened: {:?}, unknown: {:?}",
                    ip, result.opened, result.unknown
                );
            }
        }
        Err(e) => {
            error!("scan failed: {}", e);
        }
    }
    Ok(())
}
