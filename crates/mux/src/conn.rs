use std::io::{self};

use rasi_ext::{
    future::event_map::{EventMap, EventStatus},
    utils::{AsyncLockable, AsyncSpinMutex},
};

use crate::{map_event_status, Error, Session};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
enum ConnEvent {
    Send,
    StreamRecv(u32),
    StreamSend(u32),
    Accept,
}

pub struct Conn {
    session: AsyncSpinMutex<Session>,
    event_map: EventMap<ConnEvent>,
}

impl Conn {
    fn notify_stream_events(&self) -> io::Result<()> {
        todo!()
    }

    /// Write new frame to be sent to peer into provided slice.
    ///
    pub async fn send(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut session = self.session.lock().await;
            match session.send(buf) {
                Ok(send_size) => {
                    self.notify_stream_events()?;

                    return Ok(send_size);
                }
                Err(Error::Done) => {
                    self.event_map
                        .once(ConnEvent::Send, session)
                        .await
                        .map_err(map_event_status)?;

                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Write new data received from peer.
    pub async fn recv(&self, buf: &[u8]) -> io::Result<usize> {
        let mut session = self.session.lock().await;
        match session.recv(buf) {
            Ok(send_size) => return Ok(send_size),

            Err(err) => return Err(err.into()),
        }
    }

    pub async fn stream_send(&self, stream_id: u32, buf: &[u8], fin: bool) -> io::Result<usize> {
        loop {
            let mut session = self.session.lock().await;
            match session.stream_send(stream_id, buf, fin) {
                Ok(send_size) => {
                    self.event_map.notify(ConnEvent::Send, EventStatus::Ready);
                    return Ok(send_size);
                }
                Err(Error::Done) => {
                    self.event_map
                        .once(ConnEvent::StreamSend(stream_id), session)
                        .await
                        .map_err(map_event_status)?;

                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    pub async fn stream_recv(&self, stream_id: u32, buf: &mut [u8]) -> io::Result<(usize, bool)> {
        loop {
            let mut session = self.session.lock().await;
            match session.stream_recv(stream_id, buf) {
                Ok((send_size, fin)) => return Ok((send_size, fin)),
                Err(Error::Done) => {
                    self.event_map
                        .once(ConnEvent::StreamRecv(stream_id), session)
                        .await
                        .map_err(map_event_status)?;

                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    pub async fn accept(&self) -> io::Result<u32> {
        loop {
            let mut session = self.session.lock().await;
            if let Some(stream_id) = session.accept()? {
                return Ok(stream_id);
            }

            self.event_map
                .once(ConnEvent::Accept, session)
                .await
                .map_err(map_event_status)?;
        }
    }
}
