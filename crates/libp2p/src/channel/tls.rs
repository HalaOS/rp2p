use std::{
    io::{self, Read, Write},
    net::Shutdown,
    sync::Arc,
    task::{Context, Waker},
};

use boring::ssl::{
    ConnectConfiguration, MidHandshakeSslStream, SslAcceptor, SslConnector, SslMethod, SslStream,
};

use futures::FutureExt;
use multiaddr::Multiaddr;
use rasi::syscall::{CancelablePoll, Handle};
use rasi_ext::utils::{Lockable, LockableNew, SpinMutex};

use crate::{errors::P2pError, ChannelStream, HandleContext, SecureUpgrade, Transport};

use super::utils::to_sockaddr;

#[derive(Default)]
pub struct TlsSecureUpgrade;

#[allow(unused)]
struct TlsBuffer {
    is_server: bool,
    handle: Arc<Handle>,
    transport: std::sync::Arc<Box<dyn Transport>>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    read_cancel_handle: Option<Handle>,
    write_cancel_handle: Option<Handle>,
}

impl TlsBuffer {
    pub fn new(
        is_server: bool,
        handle: Arc<Handle>,
        transport: std::sync::Arc<Box<dyn Transport>>,
    ) -> Self {
        Self {
            is_server,
            handle,
            transport,
            read_waker: None,
            write_waker: None,
            read_cancel_handle: None,
            write_cancel_handle: None,
        }
    }
    pub fn register_read(&mut self, waker: Waker) {
        self.read_waker = Some(waker);
    }

    pub fn register_write(&mut self, waker: Waker) {
        self.write_waker = Some(waker);
    }

    pub fn is_read_pending(&self) -> bool {
        self.read_waker.is_some()
    }

    pub fn is_write_pending(&self) -> bool {
        self.write_waker.is_some()
    }
}

impl io::Write for TlsBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let waker = self.write_waker.take().unwrap();

        match self
            .transport
            .write(&mut Context::from_waker(&waker), &self.handle, buf)
        {
            CancelablePoll::Ready(r) => {
                log::trace!("TlsBuffer, write: {:?}", r);
                r
            }
            CancelablePoll::Pending(write_pending) => {
                log::trace!("TlsBuffer, write: pending");
                self.write_cancel_handle = write_pending;

                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Transport write pending",
                ))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(unused)]
impl io::Read for TlsBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read_waker = self.read_waker.take().unwrap();
        match self
            .transport
            .read(&mut Context::from_waker(&read_waker), &self.handle, buf)
        {
            CancelablePoll::Ready(r) => {
                self.read_waker = Some(read_waker);
                log::trace!("TlsBuffer, read: {:?}", r);
                return r;
            }
            CancelablePoll::Pending(read_pending) => {
                log::trace!("TlsBuffer, read: pending");
                self.read_cancel_handle = read_pending;

                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Transport read pending",
                ));
            }
        }
    }
}
enum TlsState {
    Handshake(Option<MidHandshakeSslStream<TlsBuffer>>),
    Stream(SslStream<TlsBuffer>),
}

struct TlsStream {
    handle: Arc<Handle>,
    transport: std::sync::Arc<Box<dyn Transport>>,
    state: SpinMutex<TlsState>,
}

impl TlsStream {
    pub fn new(
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        handshake: MidHandshakeSslStream<TlsBuffer>,
    ) -> Self {
        Self {
            handle,
            transport,
            state: SpinMutex::new(TlsState::Handshake(Some(handshake))),
        }
    }

    pub fn write(&self, cx: &mut Context<'_>, buf: &[u8]) -> CancelablePoll<io::Result<usize>> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(stream) => {
                stream.get_mut().register_write(cx.waker().clone());
                match stream.write(buf) {
                    Ok(write_size) => {
                        if write_size == 0 && stream.get_mut().is_write_pending() {
                            return CancelablePoll::Pending(None);
                        }

                        CancelablePoll::Ready(Ok(write_size))
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        CancelablePoll::Pending(None)
                    }
                    Err(err) => CancelablePoll::Ready(Err(err)),
                }
            }
            TlsState::Handshake(_) => CancelablePoll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Call handshake first",
            ))),
        }
    }

    pub fn read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> CancelablePoll<io::Result<usize>> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(stream) => {
                stream.get_mut().register_read(cx.waker().clone());
                match stream.read(buf) {
                    Ok(write_size) => {
                        if write_size == 0 && stream.get_mut().is_read_pending() {
                            return CancelablePoll::Pending(None);
                        }

                        CancelablePoll::Ready(Ok(write_size))
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        CancelablePoll::Pending(None)
                    }
                    Err(err) => CancelablePoll::Ready(Err(err)),
                }
            }
            TlsState::Handshake(_) => CancelablePoll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Call handshake first",
            ))),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(_) => self.transport.shutdown(&self.handle, how),
            TlsState::Handshake(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "Call handshake first"))
            }
        }
    }

    pub fn handshake(&self, cx: &mut Context<'_>) -> CancelablePoll<io::Result<()>> {
        let mut state = self.state.lock();
        match &mut *state {
            TlsState::Stream(_) => CancelablePoll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Already handshake successfully",
            ))),
            TlsState::Handshake(handshake) => {
                let mut handshake = handshake.take().unwrap();
                handshake.get_mut().register_read(cx.waker().clone());
                handshake.get_mut().register_write(cx.waker().clone());
                handshake.ssl_mut().set_task_waker(Some(cx.waker().clone()));

                log::trace!(
                    "server({}), handshake",
                    self.transport.is_server(&self.handle)
                );

                match handshake.handshake() {
                    Ok(stream) => {
                        log::trace!("handshake ok");
                        *state = TlsState::Stream(stream);

                        CancelablePoll::Ready(Ok(()))
                    }
                    Err(boring::ssl::HandshakeError::WouldBlock(handshake)) => {
                        log::trace!(
                            "server({}), handshake pending...",
                            self.transport.is_server(&self.handle)
                        );
                        *state = TlsState::Handshake(Some(handshake));
                        CancelablePoll::Pending(None)
                    }
                    Err(boring::ssl::HandshakeError::Failure(_)) => CancelablePoll::Ready(Err(
                        io::Error::new(io::ErrorKind::BrokenPipe, "handshake failed"),
                    )),
                    Err(boring::ssl::HandshakeError::SetupFailure(err_stack)) => {
                        CancelablePoll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            err_stack,
                        )))
                    }
                }
            }
        }
    }
}

impl ChannelStream for TlsSecureUpgrade {
    fn write(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &[u8],
    ) -> CancelablePoll<io::Result<usize>> {
        if buf.len() == 0 {
            return CancelablePoll::Ready(Ok(0));
        }

        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.write(cx, buf)
    }

    fn read(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &mut [u8],
    ) -> CancelablePoll<io::Result<usize>> {
        if buf.len() == 0 {
            return CancelablePoll::Ready(Ok(0));
        }

        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.read(cx, buf)
    }

    fn shutdown(&self, handle: &Handle, how: std::net::Shutdown) -> io::Result<()> {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.shutdown(how)
    }
}

impl HandleContext for TlsSecureUpgrade {
    fn fmt(&self, handle: &Handle, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.fmt(&stream.handle, f)
    }

    fn peer_addr(&self, handle: &Handle) -> Multiaddr {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.peer_addr(&stream.handle)
    }

    fn public_key<'a>(&self, _handle: &'a Handle) -> Option<&'a identity::PublicKey> {
        todo!()
    }

    fn is_server(&self, handle: &Handle) -> bool {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.is_server(&stream.handle)
    }

    fn local_addr(&self, handle: &Handle) -> Multiaddr {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.local_addr(&stream.handle)
    }
}

impl SecureUpgrade for TlsSecureUpgrade {
    fn upgrade_client(
        &self,
        cx: &mut Context<'_>,
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn crate::KeypairProvider>>,
    ) -> CancelablePoll<io::Result<Handle>> {
        let config = match Box::pin(make_ssl_connector(keypair)).poll_unpin(cx) {
            std::task::Poll::Ready(Ok(ssl_acceptor)) => ssl_acceptor,
            std::task::Poll::Ready(Err(err)) => return CancelablePoll::Ready(Err(err.into())),
            std::task::Poll::Pending => return CancelablePoll::Pending(None),
        };

        let addr = match to_sockaddr(&transport.peer_addr(&handle)) {
            Some(addr) => addr,
            None => {
                return CancelablePoll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TlsUpgrade: peer_addr is not a valid tcp/udp address.",
                )));
            }
        };

        let handshake = match config
            .setup_connect(
                &addr.ip().to_string(),
                TlsBuffer::new(false, handle.clone(), transport.clone()),
            )
            .map_err(|err| P2pError::BoringErrStack(err))
        {
            Ok(handshake) => handshake,
            Err(err) => {
                return CancelablePoll::Ready(Err(err.into()));
            }
        };

        CancelablePoll::Ready(Ok(Handle::new(TlsStream::new(
            handle, transport, handshake,
        ))))
    }

    fn upgrade_server(
        &self,
        cx: &mut Context<'_>,
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn crate::KeypairProvider>>,
    ) -> CancelablePoll<io::Result<Handle>> {
        let ssl_acceptor = match Box::pin(make_ssl_acceptor(keypair)).poll_unpin(cx) {
            std::task::Poll::Ready(Ok(ssl_acceptor)) => ssl_acceptor,
            std::task::Poll::Ready(Err(err)) => return CancelablePoll::Ready(Err(err.into())),
            std::task::Poll::Pending => return CancelablePoll::Pending(None),
        };

        let handshake = match ssl_acceptor
            .setup_accept(TlsBuffer::new(true, handle.clone(), transport.clone()))
            .map_err(|err| P2pError::BoringErrStack(err))
        {
            Ok(handshake) => handshake,
            Err(err) => {
                return CancelablePoll::Ready(Err(err.into()));
            }
        };

        CancelablePoll::Ready(Ok(Handle::new(TlsStream::new(
            handle, transport, handshake,
        ))))
    }

    fn handshake(
        &self,
        cx: &mut std::task::Context<'_>,
        upgrade_handle: &Handle,
    ) -> CancelablePoll<io::Result<()>> {
        let stream = upgrade_handle
            .downcast::<TlsStream>()
            .expect("Expect TlsStream");

        stream.handshake(cx)
    }
}

async fn make_ssl_acceptor(
    keypair: Arc<Box<dyn crate::KeypairProvider>>,
) -> io::Result<SslAcceptor> {
    let (cert, pk) = crate::x509::generate(&**keypair).await?;

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    let cert = boring::x509::X509::from_der(&cert)?;

    let pk = boring::pkey::PKey::from_ec_key(boring::ec::EcKey::private_key_from_der(&pk)?)?;

    builder.set_certificate(&cert)?;

    builder.set_private_key(&pk)?;

    Ok(builder.build())
}

async fn make_ssl_connector(
    keypair: Arc<Box<dyn crate::KeypairProvider>>,
) -> io::Result<ConnectConfiguration> {
    let (cert, pk) = crate::x509::generate(&**keypair).await?;

    let mut config = SslConnector::builder(SslMethod::tls())?;

    let cert = boring::x509::X509::from_der(&cert)?;

    let pk = boring::pkey::PKey::from_ec_key(boring::ec::EcKey::private_key_from_der(&pk)?)?;

    config.set_certificate(&cert)?;

    config.set_private_key(&pk)?;

    Ok(config.build().configure()?)
}
