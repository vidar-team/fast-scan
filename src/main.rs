mod cli;

use crate::cli::Arg;
use anyhow::{Result, anyhow};
use clap::Parser;
use fast_scan::{
    Error,
    scan::tcp_syn::{self},
};
use indicatif::ProgressBar;
use log::{LevelFilter, error, info};
use rayon::ThreadPoolBuilder;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
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
    let args = Arg::try_parse()?;

    let if_index = match args.if_index {
        Some(if_index) => if_index,
        None => {
            netdev::get_default_interface()
                .map_err(|e| anyhow!(e))?
                .index
        }
    };

    let pool = ThreadPoolBuilder::new().num_threads(args.thread).build()?;

    let dest_ips = args.dest_ips;
    let dest_ports = args.dest_ports;
    let count = dest_ips.len() * dest_ports.len();

    let (progress, progress_tx) = Progress::new(count);

    let scanner = tcp_syn::Scanner {
        pool: &pool,
        if_index,
        dest_ips,
        dest_ports,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 14)),
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
