use anyhow::{Result, anyhow};
use fast_scan::{
    Error,
    scan::tcp_syn::{self, ScanResult},
};
use log::{info, warn};
use rayon::ThreadPoolBuilder;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<()> {
    flexi_logger::Logger::try_with_str("debug")?.start()?;

    let pool = ThreadPoolBuilder::new().num_threads(10).build()?;
    let if_index = netdev::get_default_interface()
        .map_err(|e| anyhow!(e))?
        .index;
    let scanner = tcp_syn::Scanner {
        pool: &pool,
        if_index,
        dest_ips: vec![
            //IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 22)),
        ],
        dest_ports: (1024..=60000).collect(),
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 14)),
        src_port: rand::random(),
        timeout: Duration::from_secs(5),
    };

    let results = scanner.run().await;
    match results {
        Ok(results) => {
            for (ip, result) in results.iter() {
                info!(
                    "Scan result for {}: opened: {:?}, unknown: {:?}",
                    ip, result.opened, result.unknown
                );
            }
        }
        Err(e) => {
            if let Error::Timeout(results) = e {
                warn!("Scan timed out. Partial results:");
                for (ip, result) in results.iter() {
                    info!(
                        "Scan result for {}: opened: {:?}, unknown: {:?}",
                        ip, result.opened, result.unknown
                    );
                }
            }
        }
    }

    Ok(())
}
