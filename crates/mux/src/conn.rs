use std::{io, ops::Deref, sync::Arc};

use futures::{AsyncRead, AsyncWrite};
use rasi::executor::spawn;
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

/// Yamux connection type with asynchronous api.
#[derive(Clone)]
pub struct Conn {
    session: Arc<AsyncSpinMutex<Session>>,
    event_map: Arc<EventMap<ConnEvent>>,
}

impl Conn {
    fn notify_stream_events<S>(&self, session: &S)
    where
        S: Deref<Target = Session>,
    {
        let mut events = vec![];

        for id in session.readable() {
            events.push(ConnEvent::StreamRecv(id));
        }

        for id in session.writable() {
            events.push(ConnEvent::StreamSend(id));
        }

        if session.acceptable() {
            events.push(ConnEvent::Accept);
        }

        self.event_map.notify_all(&events, EventStatus::Ready);
    }

    /// Write new frame to be sent to peer into provided slice.
    ///
    pub async fn send(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut session = self.session.lock().await;
            match session.send(buf) {
                Ok(send_size) => {
                    self.notify_stream_events(&session);

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
    pub async fn recv(&self, buf: &[u8]) -> crate::errors::Result<usize> {
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
                Ok((send_size, fin)) => {
                    self.event_map.notify(ConnEvent::Send, EventStatus::Ready);
                    return Ok((send_size, fin));
                }
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

impl Conn {
    /// Create yamux `Conn` instance with provided parameters.
    pub fn new(window_size: u32, is_server: bool) -> Self {
        let session = Session::new(window_size, is_server);

        let conn = Conn {
            session: Arc::new(AsyncSpinMutex::new(session)),
            event_map: Default::default(),
        };

        conn
    }

    /// Create a new yamux `Conn` instance with reliable stream underneath.
    ///
    /// This function will start two event loops:
    ///
    /// - message send loop, read yamux frame from session and send to peer.
    /// - message recv loop, recv yamux frame from peer and write to session.
    pub fn new_with<R, W>(window_size: u32, is_server: bool, reader: R, writer: W) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let session = Session::new(window_size, is_server);

        let conn = Conn {
            session: Arc::new(AsyncSpinMutex::new(session)),
            event_map: Default::default(),
        };

        // spawn the recv loop
        spawn(Self::recv_loop(conn.clone(), reader));
        // spawn the send loop
        spawn(Self::send_loop(conn.clone(), writer));

        conn
    }

    async fn recv_loop<R>(mut conn: Conn, mut reader: R)
    where
        R: AsyncRead + Unpin + Send,
    {
        match Self::recv_loop_inner(&mut conn, &mut reader).await {
            Ok(_) => {
                log::info!("Yamux conn stop recv loop");
            }
            Err(err) => {
                log::error!("Yamux conn stop recv loop, {}", err);
            }
        }
    }

    async fn recv_loop_inner<R>(conn: &mut Conn, reader: &mut R) -> io::Result<()>
    where
        R: AsyncRead + Unpin + Send,
    {
        use rasi::io::AsyncReadExt;

        let mut buf = vec![0; 1024 * 4 + 12];

        loop {
            reader.read_exact(&mut buf[0..12]).await?;

            match conn.recv(&buf[..12]).await {
                Ok(_) => {
                    continue;
                }
                Err(Error::BufferTooShort(len)) => {
                    if len + 12 > buf.len() as u32 {
                        return Err(Error::Overflow.into());
                    }

                    conn.recv(&mut buf[12..len as usize + 12]).await?;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn send_loop<W>(mut conn: Conn, mut writer: W)
    where
        W: AsyncWrite + Unpin + Send,
    {
        match Self::send_loop_inner(&mut conn, &mut writer).await {
            Ok(_) => {
                log::info!("Yamux conn stop send loop");
            }
            Err(err) => {
                log::error!("Yamux conn stop send loop, {}", err);
            }
        }

        use rasi::io::AsyncWriteExt;

        _ = writer.close().await;
    }
    async fn send_loop_inner<W>(conn: &mut Conn, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        use rasi::io::AsyncWriteExt;

        let mut buf = vec![0; 1024 * 4 + 12];

        loop {
            let send_size = conn.send(&mut buf).await?;

            writer.write_all(&buf[..send_size]).await?;
        }
    }
}

#[cfg(test)]
mod tests {}
