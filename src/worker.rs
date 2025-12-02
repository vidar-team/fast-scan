use crate::Result;
use log::{debug, error};
use pcap::{BreakLoop, Device, Error as PcapError};
use rayon::ThreadPool;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

#[repr(u32)]
pub enum State {
    Stopped = 0,
    Busy = 1,
    Idle = 2,
}

pub struct Worker<'a> {
    pool: &'a ThreadPool,
    device: Device,
    tx: flume::Sender<Vec<u8>>,
    rx: flume::Receiver<Vec<u8>>,
    filter: String,
    state: Arc<AtomicU32>,
}

impl<'a> Worker<'a> {
    pub fn new(
        pool: &'a ThreadPool,
        device: Device,
        tx: flume::Sender<Vec<u8>>,
        rx: flume::Receiver<Vec<u8>>,
        filter: String,
    ) -> Self {
        debug!("worker created with filter: {}", filter);
        Self {
            pool,
            device,
            tx,
            rx,
            state: Arc::new(AtomicU32::new(State::Stopped as u32)),
            filter,
        }
    }

    pub fn spawn(self) -> Result<(BreakLoop, Arc<AtomicU32>)> {
        let mut cap = self.device.open()?.setnonblock()?;
        let break_handle = cap.breakloop_handle();
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let state = self.state.clone();

        cap.filter(&self.filter, true)?;

        self.pool.spawn(move || {
            debug!("worker started");
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        state.store(State::Busy as u32, Ordering::Relaxed);
                        if let Err(e) = tx.send(packet.data.to_vec()) {
                            error!("failed to send packet data: {}", e);
                            break;
                        }
                    }
                    Err(PcapError::NoMorePackets) => break,
                    Err(PcapError::TimeoutExpired) => match rx.try_recv() {
                        Ok(packet) => {
                            state.store(State::Busy as u32, Ordering::Relaxed);
                            if let Err(e) = cap.sendpacket(packet) {
                                error!("failed to send packet: {}", e);
                                break;
                            }
                        }
                        Err(_) => state.store(State::Idle as u32, Ordering::Relaxed),
                    },
                    Err(e) => {
                        error!("failed to capture packet: {}", e);
                        break;
                    }
                }
            }
            state.store(State::Stopped as u32, Ordering::Relaxed);
            debug!("worker stopped");
        });
        Ok((break_handle, self.state))
    }
}
