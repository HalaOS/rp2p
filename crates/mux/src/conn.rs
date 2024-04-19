use std::{io, ops::Deref, sync::Arc, task::Poll};

use futures::{AsyncRead, AsyncWrite, FutureExt};
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
    is_server: bool,
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

    /// Close `YamuxConn` with provided [`reason`](Reason)
    pub async fn close(&self, reason: Reason) -> io::Result<()> {
        let mut session = self.session.lock().await;

        session.close(reason)?;

        Ok(())
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
            log::trace!("stream, id={}, recv", stream_id);
            let mut session = self.session.lock().await;
            match session.stream_recv(stream_id, buf) {
                Ok((send_size, fin)) => {
                    log::trace!(
                        "stream, id={}, recv_size={}, fin={}",
                        stream_id,
                        send_size,
                        fin
                    );
                    self.event_map.notify(ConnEvent::Send, EventStatus::Ready);
                    return Ok((send_size, fin));
                }
                Err(Error::Done) => {
                    log::trace!("stream, id={}, recv pending.", stream_id,);
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

    pub async fn stream_accept(&self) -> io::Result<YamuxStream> {
        loop {
            let mut session = self.session.lock().await;
            if let Some(stream_id) = session.accept()? {
                return Ok(YamuxStream::new(stream_id, self.clone()));
            }

            self.event_map
                .once(ConnEvent::Accept, session)
                .await
                .map_err(map_event_status)?;
        }
    }

    /// Open new outbound stream.
    pub async fn stream_open(&self) -> io::Result<YamuxStream> {
        let mut session = self.session.lock().await;

        let stream_id = session.open()?;

        self.event_map.notify(ConnEvent::Send, EventStatus::Ready);

        Ok(YamuxStream::new(stream_id, self.clone()))
    }

    /// Returns true if all the data has been read from the specified stream.
    ///
    /// This instructs the application that all the data received from the peer on the stream has been read, and there won’t be anymore in the future.
    ///
    /// Basically this returns true when the peer either set the fin flag for the stream, or sent *_FRAME with RST flag.
    pub async fn stream_finished(&self, stream_id: u32) -> bool {
        let session = self.session.lock().await;

        session.stream_finished(stream_id)
    }

    /// Elegantly close stream.
    pub async fn stream_close(&self, stream_id: u32) -> io::Result<()> {
        self.stream_send(stream_id, b"", true).await?;

        // stream object dropped, reset the stream immediately
        if !self.stream_finished(stream_id).await {
            let mut session = self.session.lock().await;

            session.stream_reset(stream_id)?;
        }

        Ok(())
    }
}

impl YamuxConn {
    /// Create yamux `Conn` instance with provided parameters.
    pub fn new(window_size: u32, is_server: bool) -> Self {
        let session = Session::new(window_size, is_server);

        let conn = YamuxConn {
            session: Arc::new(AsyncSpinMutex::new(session)),
            event_map: Default::default(),
            is_server,
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
            is_server,
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

            log::trace!(
                "recv data from peer, is_server={}, len={}",
                conn.is_server,
                12
            );

            match conn.recv(&buf[..12]).await {
                Ok(_) => {
                    continue;
                }
                Err(Error::BufferTooShort(len)) => {
                    if len > buf.len() as u32 {
                        return Err(Error::Overflow.into());
                    }

                    reader.read_exact(&mut buf[12..len as usize]).await?;

                    log::trace!("yamux conn recv loop, recv data, len={}", len);

                    conn.recv(&buf[..len as usize]).await?;
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

            buf[..12].fill(0x0);

            log::trace!(
                "yamux send loop, transfer data to peer, is_server={}, len={}",
                conn.is_server,
                send_size
            );
        }
    }
}

/// Stream object with [`Drop`] trait.
struct RawStream(u32, YamuxConn);

impl Drop for RawStream {
    fn drop(&mut self) {
        let stream_id = self.0;
        let conn = self.1.clone();
        spawn(async move {
            if let Err(err) = conn.stream_close(stream_id).await {
                log::error!("Close stream with error: {}", err);
            }
        })
    }
}

/// Yamux stream type with asynchronous api.
pub struct YamuxStream {
    raw: Arc<RawStream>,
}

impl YamuxStream {
    fn new(stream_id: u32, conn: YamuxConn) -> Self {
        Self {
            raw: Arc::new(RawStream(stream_id, conn)),
        }
    }

    /// Returns stream id.
    pub fn stream_id(&self) -> u32 {
        self.raw.0
    }
}

impl AsyncWrite for YamuxStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Box::pin(self.raw.1.stream_send(self.raw.0, buf, false)).poll_unpin(cx)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Box::pin(self.raw.1.stream_close(self.raw.0)).poll_unpin(cx)
    }
}

impl AsyncRead for YamuxStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Box::pin(self.raw.1.stream_recv(self.raw.0, buf))
            .poll_unpin(cx)
            .map(|r| match r {
                Ok((readsize, fin)) => {
                    log::trace!("yamux AsyncRead: len={}, fin={}", readsize, fin);
                    return Ok(readsize);
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::BrokenPipe {
                        Ok(0)
                    } else {
                        Err(err)
                    }
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use futures::{AsyncReadExt, AsyncWriteExt};
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

            // pretty_env_logger::init_timed();
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

            let stream = conn.stream_accept().await.unwrap();

            assert_eq!(stream.stream_id(), 1);

            let mut stream = conn.stream_open().await.unwrap();

            assert_eq!(stream.stream_id(), 2);

            stream.write_all(b"hello world").await.unwrap();
        });

        let (read, write) = TcpStream::connect(local_addr).await.unwrap().split();

        let conn = YamuxConn::new_with(INIT_WINDOW_SIZE, false, read, write);

        let stream = conn.stream_open().await.unwrap();

        assert_eq!(stream.stream_id(), 1);

        let mut stream = conn.stream_accept().await.unwrap();

        assert_eq!(stream.stream_id(), 2);

        let mut buf = vec![0; 100];

        let read_size = stream.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..read_size], b"hello world");
    }
}
