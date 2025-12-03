mod cli;

use crate::cli::{Arg, Command, TcpSynArg};
use anyhow::{Result, anyhow, bail};
use clap::Parser;
use fast_scan::{
    Error,
    interface::Interface,
    scan::tcp_syn::{self},
};
use indicatif::ProgressBar;
use log::{LevelFilter, error, info, warn};
use rayon::ThreadPoolBuilder;
use std::{net::IpAddr, time::Duration};
use tokio::time::Instant;

struct Progress<T> {
    progress_rx: flume::Receiver<T>,
    progress: ProgressBar,
}

impl<T> Progress<T> {
    fn new(total: usize) -> (Self, flume::Sender<T>) {
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
        while self.progress_rx.recv_async().await.is_ok() {
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

fn ip_version_match(a: &IpAddr, b: &IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(_), IpAddr::V4(_)) => true,
        (IpAddr::V4(_), IpAddr::V6(_)) => false,
        (IpAddr::V6(_), IpAddr::V4(_)) => false,
        (IpAddr::V6(_), IpAddr::V6(_)) => true,
    }
}

async fn list_interfaces() -> Result<()> {
    info!("{:#?}", Interface::list()?);
    Ok(())
}

async fn tcp_syn(arg: TcpSynArg) -> Result<()> {
    let pool = ThreadPoolBuilder::new().num_threads(arg.thread).build()?;

    let dest_ips = arg
        .dest_nets
        .iter()
        .flat_map(|ip| ip.hosts())
        .collect::<Vec<IpAddr>>();
    // SAFETY: dest_ips is non-empty because dest_nets is required
    let first_dest_ip = dest_ips.first().unwrap();
    if dest_ips
        .iter()
        .any(|ip| !ip_version_match(ip, first_dest_ip))
    {
        bail!("mixed ipv4 and ipv6 addresses are not supported");
    }
    let src_ip = match arg.src_ip {
        Some(ip) => ip,
        None => netdev::get_default_interface()
            .map_err(|e| anyhow!(e))?
            .ip_addrs()
            .into_iter()
            .find(|ip| ip_version_match(ip, first_dest_ip))
            .ok_or(anyhow!("no default address"))?,
    };

    let count = dest_ips.len() * arg.dest_ports.len();

    info!(
        "start tcp syn scan, if_index: {}, src_ip: {}, dest_nets: {:#?}, number of dest_ports: {}",
        arg.if_index,
        src_ip,
        arg.dest_nets,
        arg.dest_ports.len()
    );

    let (progress, progress_tx) = Progress::new(count);

    let scanner = tcp_syn::Scanner {
        pool: &pool,
        if_index: arg.if_index,
        dest_nets: arg.dest_nets,
        dest_ports: arg.dest_ports,
        src_ip,
        src_port: rand::random(),
        timeout: Duration::from_secs(2),
        wait_idle: arg.wait_idle,
        send_buffer_size: arg.send_buffer_size,
        send_progress_tx: None,
        recv_progress_tx: Some(progress_tx),
    };

    tokio::spawn(progress.run());
    let start = Instant::now();
    match scanner.run().await {
        Ok(results) => {
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
        Err(Error::Timeout(results)) => {
            warn!("scan timed out");
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
        Err(Error::WorkerAbortedWith(results)) => {
            warn!("worker aborted");
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
    let duration = Instant::now() - start;
    info!(
        "scan completed in {:.2} secs, {:.2} ports/sec",
        duration.as_secs_f64(),
        count as f64 / duration.as_secs_f64()
    );

    Ok(())
}
