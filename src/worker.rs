use crate::Result;
use atomic_enum::atomic_enum;
use log::{debug, error};
use pcap::{BreakLoop, Device, Error as PcapError};
use rayon::ThreadPool;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

#[atomic_enum]
#[derive(PartialEq)]
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
    state: Arc<AtomicState>,
    state_changed_on: Arc<AtomicU64>,
    time: Instant,
}

impl<'a> Worker<'a> {
    pub fn new(
        pool: &'a ThreadPool,
        device: Device,
        tx: flume::Sender<Vec<u8>>,
        rx: flume::Receiver<Vec<u8>>,
        filter: String,
    ) -> Self {
        Self {
            pool,
            device,
            tx,
            rx,
            time: Instant::now(),
            state: Arc::new(AtomicState::new(State::Stopped)),
            state_changed_on: Arc::new(AtomicU64::new(0)),
            filter,
        }
    }

    fn set_state(
        new: State,
        state: Arc<AtomicState>,
        state_changed_on: Arc<AtomicU64>,
        time: Instant,
    ) {
        if state.load(Ordering::Acquire) == new {
            return;
        }

        Self::set_changed_on(state_changed_on, time);
        state.swap(new, Ordering::SeqCst);
    }

    fn set_changed_on(state_changed_on: Arc<AtomicU64>, time: Instant) -> u64 {
        state_changed_on.swap(
            Instant::now().duration_since(time).as_millis() as u64,
            Ordering::SeqCst,
        )
    }

    pub fn spawn(self) -> Result<(BreakLoop, Arc<AtomicState>, Arc<AtomicU64>, Instant)> {
        let mut cap = self.device.open()?.setnonblock()?;
        let break_handle = cap.breakloop_handle();
        let tx = self.tx.clone();
        let rx = self.rx.clone();
        let state = self.state.clone();
        let state_changed_on = self.state_changed_on.clone();

        cap.filter(&self.filter, true)?;

        self.pool.spawn(move || {
            debug!("worker started");
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        Self::set_state(
                            State::Busy,
                            state.clone(),
                            state_changed_on.clone(),
                            self.time,
                        );
                        if let Err(e) = tx.send(packet.data.to_vec()) {
                            error!("failed to send packet data from capture: {}", e);
                            break;
                        }
                    }
                    Err(PcapError::NoMorePackets) => break,
                    Err(PcapError::TimeoutExpired) => match rx.try_recv() {
                        Ok(packet) => {
                            Self::set_state(
                                State::Busy,
                                state.clone(),
                                state_changed_on.clone(),
                                self.time,
                            );
                            if let Err(e) = cap.sendpacket(packet) {
                                error!("failed to send packet: {}", e);
                                break;
                            }
                        }
                        Err(_) => Self::set_state(
                            State::Idle,
                            state.clone(),
                            state_changed_on.clone(),
                            self.time,
                        ),
                    },
                    Err(e) => {
                        error!("failed to recv packet: {}", e);
                        break;
                    }
                }
            }
            Self::set_state(
                State::Stopped,
                state.clone(),
                state_changed_on.clone(),
                self.time,
            );
            debug!("worker stopped");
        });
        Ok((break_handle, self.state, self.state_changed_on, self.time))
    }
}
