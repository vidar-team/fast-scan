use crate::Result;
use log::{debug, error};
use pcap::{BreakLoop, Capture, Device};
use rayon::ThreadPool;
use std::time::Duration;

pub struct Worker<'a> {
    pool: &'a ThreadPool,
    device: Device,
    filter: String,
    timeout: Option<Duration>,
}

impl<'a> Worker<'a> {
    pub fn new(
        pool: &'a ThreadPool,
        device: Device,
        filter: String,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            pool,
            device,
            filter,
            timeout,
        }
    }

    pub fn spawn_rx(&self) -> Result<(flume::Receiver<Vec<u8>>, BreakLoop)> {
        let cap = Capture::from_device(self.device.clone())?;
        let mut cap = match self.timeout {
            Some(timeout) => cap.timeout(timeout.as_millis() as i32).open(),
            None => cap.open(),
        }?;

        let break_handle = cap.breakloop_handle();
        let (tx, rx) = flume::unbounded::<Vec<u8>>();

        cap.filter(&self.filter, true)?;

        self.pool.spawn(move || {
            debug!("worker rx started");
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if tx.send(packet.data.to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("failed to recv packet from capture: {}", e);
                        break;
                    }
                }
            }
            debug!("worker rx stopped");
        });
        Ok((rx, break_handle))
    }

    pub fn spawn_tx(&self) -> Result<(flume::Sender<Vec<u8>>, BreakLoop)> {
        let mut cap = self.device.clone().open()?;
        let break_handle = cap.breakloop_handle();
        let (tx, rx) = flume::unbounded::<Vec<u8>>();

        self.pool.spawn(move || {
            debug!("worker tx started");
            while let Ok(packet) = rx.recv() {
                if let Err(e) = cap.sendpacket(packet) {
                    error!("failed to send packet data to capture: {}", e);
                    break;
                }
            }
            debug!("worker tx stopped");
        });
        Ok((tx, break_handle))
    }

    #[allow(clippy::type_complexity)]
    pub fn spawn(
        &self,
    ) -> Result<(
        (flume::Sender<Vec<u8>>, BreakLoop),
        (flume::Receiver<Vec<u8>>, BreakLoop),
    )> {
        Ok((self.spawn_tx()?, self.spawn_rx()?))
    }
}
