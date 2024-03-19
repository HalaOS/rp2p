use std::{
    io,
    net::{IpAddr, SocketAddr},
};

use multiaddr::{Multiaddr, Protocol};
use rasi::syscall::{global_network, CancelablePoll, Handle, Network};

use crate::{ChannelIo, HandleContext, SecureUpgrade, Transport};

pub struct TcpTransport;

struct TcpStream {
    is_server: bool,
    local_addr: Multiaddr,
    peer_addr: Multiaddr,
    handle: Handle,
    network: &'static dyn Network,
}

fn to_sockadrr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();

    let ip = match iter.next()? {
        Protocol::Ip4(ip) => IpAddr::from(ip),
        Protocol::Ip6(ip) => IpAddr::from(ip),
        _ => return None,
    };

    if let Protocol::Tcp(port) = iter.next()? {
        return Some(SocketAddr::new(ip, port));
    }

    None
}

impl ChannelIo for TcpTransport {
    fn write(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &rasi::syscall::Handle,
        buf: &[u8],
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<usize>> {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream
            .network
            .tcp_stream_write(cx.waker().clone(), &stream.handle, buf, pending)
    }

    fn read(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &rasi::syscall::Handle,
        buf: &mut [u8],
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<usize>> {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream
            .network
            .tcp_stream_read(cx.waker().clone(), &stream.handle, buf, pending)
    }

    fn shutdown(
        &self,
        handle: &rasi::syscall::Handle,
        how: std::net::Shutdown,
    ) -> std::io::Result<()> {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream.network.tcp_stream_shutdown(&stream.handle, how)
    }
}

impl HandleContext for TcpTransport {
    fn fmt(
        &self,
        handle: &rasi::syscall::Handle,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        write!(f, "TcpStream {}=>{}", stream.local_addr, stream.peer_addr)
    }

    fn peer_addr<'a>(&self, handle: &'a rasi::syscall::Handle) -> &'a multiaddr::Multiaddr {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        &stream.local_addr
    }

    fn public_key<'a>(
        &self,
        _handle: &'a rasi::syscall::Handle,
    ) -> Option<&'a identity::PublicKey> {
        None
    }

    fn is_server(&self, handle: &rasi::syscall::Handle) -> bool {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream.is_server
    }
}

impl Transport for TcpTransport {
    fn multiaddr_hint(&self, addr: &multiaddr::Multiaddr) -> bool {
        let stack = addr.protocol_stack().collect::<Vec<_>>();

        if stack.len() > 1 {
            if stack[1] == "tcp" {
                return true;
            }
        }

        return false;
    }

    fn bind(
        &self,
        cx: &mut std::task::Context<'_>,
        _keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
        laddr: &multiaddr::Multiaddr,
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<rasi::syscall::Handle>> {
        let network = global_network();

        let laddr = match to_sockadrr(laddr) {
            Some(laddr) => laddr,
            None => {
                return CancelablePoll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid multiaddr for tcp transport: {}", laddr),
                )))
            }
        };

        network.tcp_listener_bind(cx.waker().clone(), &[laddr], pending)
    }

    fn accept(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &rasi::syscall::Handle,
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<rasi::syscall::Handle>> {
        let network = global_network();

        match network.tcp_listener_accept(cx.waker().clone(), handle, pending) {
            CancelablePoll::Ready(Ok((stream_handle, raddr))) => {
                let laddr = match network.tcp_listener_local_addr(handle) {
                    Ok(laddr) => laddr,
                    Err(err) => return CancelablePoll::Ready(Err(err)),
                };

                let mut local_addr = Multiaddr::from(laddr.ip());

                local_addr.push(Protocol::Tcp(laddr.port()));

                let mut peer_addr = Multiaddr::from(raddr.ip());

                peer_addr.push(Protocol::Tcp(raddr.port()));

                CancelablePoll::Ready(Ok(Handle::new(TcpStream {
                    is_server: true,
                    handle: stream_handle,
                    local_addr,
                    peer_addr,
                    network,
                })))
            }
            CancelablePoll::Ready(Err(err)) => return CancelablePoll::Ready(Err(err)),
            CancelablePoll::Pending(pending) => return CancelablePoll::Pending(pending),
        }
    }

    fn connect(
        &self,
        cx: &mut std::task::Context<'_>,
        raddr: &multiaddr::Multiaddr,
        _keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<rasi::syscall::Handle>> {
        let network = global_network();

        let raddr = match to_sockadrr(raddr) {
            Some(laddr) => laddr,
            None => {
                return CancelablePoll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid multiaddr for tcp transport: {}", raddr),
                )))
            }
        };

        match network.tcp_stream_connect(cx.waker().clone(), &[raddr], pending) {
            CancelablePoll::Ready(Ok(stream_handle)) => {
                let laddr = match network.tcp_stream_local_addr(&stream_handle) {
                    Ok(laddr) => laddr,
                    Err(err) => return CancelablePoll::Ready(Err(err)),
                };

                let raddr = match network.tcp_stream_remote_addr(&stream_handle) {
                    Ok(laddr) => laddr,
                    Err(err) => return CancelablePoll::Ready(Err(err)),
                };

                let mut local_addr = Multiaddr::from(laddr.ip());

                local_addr.push(Protocol::Tcp(laddr.port()));

                let mut peer_addr = Multiaddr::from(raddr.ip());

                peer_addr.push(Protocol::Tcp(raddr.port()));

                CancelablePoll::Ready(Ok(Handle::new(TcpStream {
                    is_server: true,
                    handle: stream_handle,
                    local_addr,
                    peer_addr,
                    network,
                })))
            }
            CancelablePoll::Ready(Err(err)) => return CancelablePoll::Ready(Err(err)),
            CancelablePoll::Pending(pending) => return CancelablePoll::Pending(pending),
        }
    }
}

pub struct TlsSecureUpgrade;

struct TlsStream {
    handle: Handle,
    transport: std::sync::Arc<Box<dyn Transport>>,
}

impl ChannelIo for TlsSecureUpgrade {
    fn write(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &[u8],
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>> {
        todo!()
    }

    fn read(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &mut [u8],
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>> {
        todo!()
    }

    fn shutdown(&self, handle: &Handle, how: std::net::Shutdown) -> io::Result<()> {
        todo!()
    }
}

impl HandleContext for TlsSecureUpgrade {
    fn fmt(&self, handle: &Handle, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }

    fn peer_addr<'a>(&self, handle: &'a Handle) -> &'a Multiaddr {
        todo!()
    }

    fn public_key<'a>(&self, handle: &'a Handle) -> Option<&'a identity::PublicKey> {
        todo!()
    }

    fn is_server(&self, handle: &Handle) -> bool {
        todo!()
    }
}

impl SecureUpgrade for TlsSecureUpgrade {
    fn upgrade_client(
        &self,
        handle: Handle,
        transport: std::sync::Arc<Box<dyn Transport>>,
        keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
    ) -> io::Result<Handle> {
        todo!()
    }

    fn upgrade_server(
        &self,
        handle: Handle,
        transport: std::sync::Arc<Box<dyn Transport>>,
        keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
    ) -> io::Result<Handle> {
        todo!()
    }

    fn handshake(
        &self,
        cx: &mut std::task::Context<'_>,
        upgrade_handle: &Handle,
        pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<identity::PublicKey>> {
        todo!()
    }
}
