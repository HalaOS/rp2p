use std::io;

use multiaddr::{Multiaddr, Protocol};
use rasi::syscall::{global_network, CancelablePoll, Handle, Network};

use crate::{ChannelIo, HandleContext, Transport};

use super::utils::to_sockaddr;

#[derive(Default)]
pub struct TcpTransport;

struct TcpStream {
    is_server: bool,
    local_addr: Multiaddr,
    peer_addr: Multiaddr,
    handle: Handle,
    network: &'static dyn Network,
}

impl ChannelIo for TcpTransport {
    fn write(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &rasi::syscall::Handle,
        buf: &[u8],
    ) -> rasi::syscall::CancelablePoll<std::io::Result<usize>> {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream
            .network
            .tcp_stream_write(cx.waker().clone(), &stream.handle, buf)
    }

    fn read(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &rasi::syscall::Handle,
        buf: &mut [u8],
    ) -> rasi::syscall::CancelablePoll<std::io::Result<usize>> {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream
            .network
            .tcp_stream_read(cx.waker().clone(), &stream.handle, buf)
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

    fn peer_addr(&self, handle: &rasi::syscall::Handle) -> multiaddr::Multiaddr {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream.local_addr.clone()
    }

    fn local_addr(&self, handle: &Handle) -> Multiaddr {
        let stream = handle.downcast::<TcpStream>().expect("Expect TcpStream");

        stream.local_addr.clone()
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
    ) -> rasi::syscall::CancelablePoll<std::io::Result<rasi::syscall::Handle>> {
        let network = global_network();

        let laddr = match to_sockaddr(laddr) {
            Some(laddr) => laddr,
            None => {
                return CancelablePoll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid multiaddr for tcp transport: {}", laddr),
                )))
            }
        };

        network.tcp_listener_bind(cx.waker().clone(), &[laddr])
    }

    fn listener_local_addr(&self, handle: &Handle) -> io::Result<Multiaddr> {
        let network = global_network();

        network.tcp_listener_local_addr(handle).map(|laddr| {
            let mut local_addr = Multiaddr::from(laddr.ip());

            local_addr.push(Protocol::Tcp(laddr.port()));

            local_addr
        })
    }

    fn accept(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &rasi::syscall::Handle,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<rasi::syscall::Handle>> {
        let network = global_network();

        match network.tcp_listener_accept(cx.waker().clone(), handle) {
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
    ) -> rasi::syscall::CancelablePoll<std::io::Result<rasi::syscall::Handle>> {
        let network = global_network();

        let raddr = match to_sockaddr(raddr) {
            Some(laddr) => laddr,
            None => {
                return CancelablePoll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid multiaddr for tcp transport: {}", raddr),
                )))
            }
        };

        match network.tcp_stream_connect(cx.waker().clone(), &[raddr]) {
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
                    is_server: false,
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
