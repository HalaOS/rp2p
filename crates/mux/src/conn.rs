use std::{io, ops::Deref, sync::Arc};

use futures::{AsyncRead, AsyncWrite};
use rasi::executor::spawn;
use rasi_ext::{
    future::event_map::{EventMap, EventStatus},
    utils::{AsyncLockable, AsyncSpinMutex},
};

use crate::{map_event_status, Error, Reason, Session};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
enum ConnEvent {
    Send,
    StreamRecv(u32),
    StreamSend(u32),
    Accept,
}

/// Yamux connection type with asynchronous api.
#[derive(Clone)]
pub struct YamuxConn {
    session: Arc<AsyncSpinMutex<Session>>,
    event_map: Arc<EventMap<ConnEvent>>,
}

impl YamuxConn {
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

            log::trace!("send data.");

            match session.send(buf) {
                Ok(send_size) => {
                    self.notify_stream_events(&session);

                    return Ok(send_size);
                }
                Err(Error::Done) => {
                    log::trace!("send data. waiting");
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
            Ok(send_size) => {
                self.notify_stream_events(&session);
                return Ok(send_size);
            }

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

    pub async fn stream_accept(&self) -> io::Result<u32> {
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

    pub async fn close(&self, reason: Reason) -> io::Result<()> {
        let mut session = self.session.lock().await;

        session.close(reason)?;

        Ok(())
    }

    /// Open new outbound stream.
    pub async fn stream_open(&self) -> io::Result<u32> {
        let mut session = self.session.lock().await;

        let stream_id = session.open()?;

        self.event_map.notify(ConnEvent::Send, EventStatus::Ready);

        Ok(stream_id)
    }
}

impl YamuxConn {
    /// Create yamux `Conn` instance with provided parameters.
    pub fn new(window_size: u32, is_server: bool) -> Self {
        let session = Session::new(window_size, is_server);

        let conn = YamuxConn {
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

        let conn = YamuxConn {
            session: Arc::new(AsyncSpinMutex::new(session)),
            event_map: Default::default(),
        };

        // spawn the recv loop
        spawn(Self::recv_loop(conn.clone(), reader));
        // spawn the send loop
        spawn(Self::send_loop(conn.clone(), writer));

        conn
    }

    async fn recv_loop<R>(mut conn: YamuxConn, mut reader: R)
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

        // Close session.
        _ = conn.close(Reason::Normal).await;
    }

    async fn recv_loop_inner<R>(conn: &mut YamuxConn, reader: &mut R) -> io::Result<()>
    where
        R: AsyncRead + Unpin + Send,
    {
        use rasi::io::AsyncReadExt;

        let mut buf = vec![0; 1024 * 4 + 12];

        loop {
            reader.read_exact(&mut buf[0..12]).await?;

            log::trace!(target:"RecvLoop", "recv data from peer, len={}",  12);

            match conn.recv(&buf[..12]).await {
                Ok(_) => {
                    continue;
                }
                Err(Error::BufferTooShort(len)) => {
                    if len + 12 > buf.len() as u32 {
                        return Err(Error::Overflow.into());
                    }

                    let len = len as usize + 12;

                    reader.read_exact(&mut buf[12..len]).await?;

                    log::trace!("yamux conn recv loop, recv data, len={}", len);

                    conn.recv(&buf[12..len]).await?;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn send_loop<W>(mut conn: YamuxConn, mut writer: W)
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
    async fn send_loop_inner<W>(conn: &mut YamuxConn, writer: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        use rasi::io::AsyncWriteExt;

        let mut buf = vec![0; 1024 * 4 + 12];

        loop {
            let send_size: usize = conn.send(&mut buf).await?;

            writer.write_all(&buf[..send_size]).await?;

            log::trace!("yamux send loop, transfer data to peer, len={}", send_size);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use rasi::net::{TcpListener, TcpStream};
    use rasi_default::{
        executor::register_futures_executor, net::register_mio_network, time::register_mio_timer,
    };

    use crate::INIT_WINDOW_SIZE;

    use super::*;

    fn init() {
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            register_mio_network();
            register_mio_timer();
            register_futures_executor().unwrap();

            pretty_env_logger::init_timed();
        });
    }

    #[futures_test::test]
    async fn test_conn() {
        init();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let local_addr = listener.local_addr().unwrap();

        spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();

            let (read, write) = stream.split();

            let conn = YamuxConn::new_with(INIT_WINDOW_SIZE, true, read, write);

            let stream_id = conn.stream_accept().await.unwrap();

            assert_eq!(stream_id, 1);

            let stream_id = conn.stream_open().await.unwrap();

            assert_eq!(stream_id, 2);
        });

        let (read, write) = TcpStream::connect(local_addr).await.unwrap().split();

        let conn = YamuxConn::new_with(INIT_WINDOW_SIZE, false, read, write);

        let stream_id = conn.stream_open().await.unwrap();

        assert_eq!(stream_id, 1);

        let stream_id = conn.stream_accept().await.unwrap();

        assert_eq!(stream_id, 2);
    }
}
