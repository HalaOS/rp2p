use std::{
    io::{self, Read, Write},
    net::Shutdown,
    sync::Arc,
    task::{Context, Waker},
};

use boring::ssl::{MidHandshakeSslStream, SslAcceptor, SslConnector, SslMethod, SslStream};
use bytes::BytesMut;
use multiaddr::Multiaddr;
use rasi::syscall::{CancelablePoll, Handle};
use rasi_ext::utils::{Lockable, LockableNew, SpinMutex};

use crate::{errors::P2pError, ChannelIo, HandleContext, SecureUpgrade, Transport};

pub struct TlsSecureUpgrade;

#[allow(unused)]
struct TlsBuffer {
    handle: Arc<Handle>,
    transport: std::sync::Arc<Box<dyn Transport>>,
    send_buf: Option<BytesMut>,
    recv_buf: Option<BytesMut>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl TlsBuffer {
    pub fn new(handle: Arc<Handle>, transport: std::sync::Arc<Box<dyn Transport>>) -> Self {
        Self {
            handle,
            transport,
            send_buf: None,
            recv_buf: None,
            read_waker: None,
            write_waker: None,
        }
    }
    pub fn register_read(&mut self, waker: Waker) {
        self.read_waker = Some(waker);
    }

    pub fn register_write(&mut self, waker: Waker) {
        self.write_waker = Some(waker);
    }
}

#[allow(unused)]
impl io::Write for TlsBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> io::Result<()> {
        todo!()
    }
}

#[allow(unused)]
impl io::Read for TlsBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
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

    pub fn write(&self, cx: &mut Context<'_>, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(stream) => {
                stream.get_mut().register_write(cx.waker().clone());
                stream.write(buf)
            }
            TlsState::Handshake(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "Call handshake first"))
            }
        }
    }

    pub fn read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(stream) => {
                stream.get_mut().register_read(cx.waker().clone());
                stream.read(buf)
            }
            TlsState::Handshake(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "Call handshake first"))
            }
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

                match handshake.handshake() {
                    Ok(stream) => {
                        *state = TlsState::Stream(stream);

                        return CancelablePoll::Ready(Ok(()));
                    }
                    Err(boring::ssl::HandshakeError::WouldBlock(handshake)) => {
                        *state = TlsState::Handshake(Some(handshake));
                        return CancelablePoll::Pending(None);
                    }
                    Err(_) => todo!(),
                }
            }
        }
    }
}

impl ChannelIo for TlsSecureUpgrade {
    fn write(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &[u8],
        _pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>> {
        if buf.len() == 0 {
            return CancelablePoll::Ready(Ok(0));
        }

        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        match stream.write(cx, buf) {
            Ok(write_size) => {
                // the buf is full.
                if write_size == 0 {
                    return CancelablePoll::Pending(None);
                }

                return CancelablePoll::Ready(Ok(write_size));
            }
            Err(err) => {
                return CancelablePoll::Ready(Err(err));
            }
        }
    }

    fn read(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &mut [u8],
        _pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>> {
        if buf.len() == 0 {
            return CancelablePoll::Ready(Ok(0));
        }

        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        match stream.read(cx, buf) {
            Ok(read_size) => {
                // the buf is empty.
                if read_size == 0 {
                    return CancelablePoll::Pending(None);
                }

                return CancelablePoll::Ready(Ok(read_size));
            }
            Err(err) => {
                return CancelablePoll::Ready(Err(err));
            }
        }
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

    fn peer_addr<'a>(&self, handle: &'a Handle) -> &'a Multiaddr {
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
}

impl SecureUpgrade for TlsSecureUpgrade {
    fn upgrade_client(
        &self,
        handle: Handle,
        transport: std::sync::Arc<Box<dyn Transport>>,
        _keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
    ) -> io::Result<Handle> {
        let config = SslConnector::builder(SslMethod::tls()).unwrap();

        let config = config.build().configure().unwrap();

        let handle = Arc::new(handle);

        let handshake = config
            .setup_connect("", TlsBuffer::new(handle.clone(), transport.clone()))
            .map_err(|err| P2pError::BoringErrStack(err))?;

        Ok(Handle::new(TlsStream::new(handle, transport, handshake)))
    }

    fn upgrade_server(
        &self,
        handle: Handle,
        transport: std::sync::Arc<Box<dyn Transport>>,
        _keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
    ) -> io::Result<Handle> {
        let builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

        let ssl_acceptor = builder.build();

        let handle = Arc::new(handle);

        let handshake = ssl_acceptor
            .setup_accept(TlsBuffer::new(handle.clone(), transport.clone()))
            .map_err(|err| P2pError::BoringErrStack(err))?;

        Ok(Handle::new(TlsStream::new(handle, transport, handshake)))
    }

    fn handshake(
        &self,
        cx: &mut std::task::Context<'_>,
        upgrade_handle: &Handle,
        _pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<()>> {
        let stream = upgrade_handle
            .downcast::<TlsStream>()
            .expect("Expect TlsStream");

        stream.handshake(cx)
    }
}
