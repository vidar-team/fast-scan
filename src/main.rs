use anyhow::{Result, anyhow};
use fast_scan::{
    Error,
    scan::tcp_syn::{self, ScanResult},
};
use ipnet::Ipv4Net;
use log::{info, warn};
use rayon::ThreadPoolBuilder;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio::{task::JoinSet, time::Instant};

#[tokio::main]
async fn main() -> Result<()> {
    flexi_logger::Logger::try_with_str("debug")?.start()?;

    let pool = ThreadPoolBuilder::new().num_threads(10).build()?;
    let interface = netdev::get_default_interface().map_err(|e| anyhow!(e))?;
    info!(
        "Using interface: {} ({})",
        interface.name,
        interface.friendly_name.unwrap_or("<unknown>".to_string())
    );
    let if_index = interface.index;
    let scanner = tcp_syn::Scanner {
        pool: &pool,
        if_index,
        dest_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))],
        dest_ports: (1024..=65535).collect(),
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 14)),
        src_port: rand::random(),
        wait_after_send: Duration::from_micros(1),
        timeout: Duration::from_secs(5),
    };

    let start = Instant::now();
    let results = scanner.run().await;
    let duration = Instant::now() - start;
    info!(
        "Scan completed in {:.2} secs, {:.2} ports/sec",
        duration.as_secs(),
        (scanner.dest_ips.len() * scanner.dest_ports.len()) as f64 / duration.as_secs_f64()
    );

    match results {
        Ok(results) => {
            for (ip, result) in results.iter() {
                if !result.opened.is_empty() {
                    info!(
                        "Scan result for {}: opened: {:?}, unknown: {:?}",
                        ip, result.opened, result.unknown
                    );
                }
            }
        }
        Err(e) => {
            if let Error::Timeout(results) = e {
                warn!("Scan timed out. Partial results:");
                for (ip, result) in results.iter() {
                    if !result.opened.is_empty() {
                        info!(
                            "Scan result for {}: opened: {:?}, unknown: {:?}",
                            ip, result.opened, result.unknown
                        );
                    }
                }
            } else {
                return Err(anyhow!(e));
            }
        }
    }

    Ok(())
}
