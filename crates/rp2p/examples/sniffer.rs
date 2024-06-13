//! This is an example program to sniff the topology of a libp2p network

use std::{io, time::Duration};

use clap::Parser;
use rasi::{executor::block_on, time::sleep};
use rasi_default::{
    executor::register_futures_executor, net::register_mio_network, time::register_mio_timer,
};
use rp2p::{multiaddr::Multiaddr, SwitchBuilder};
use rp2p_conn_pool::ConnPoolWithPing;
use rp2p_hostkey::memory::MemoryHostKey;
use rp2p_quic::QuicTransport;
use rp2p_route_table::memory::MemoryRouteTable;
use rp2p_tcp::TcpTransport;

fn clap_parse_multiaddr(s: &str) -> Result<Vec<Multiaddr>, String> {
    let addrs = s
        .split(";")
        .map(|v| Multiaddr::try_from(v))
        .collect::<Result<Vec<Multiaddr>, rp2p::multiaddr::Error>>()
        .map_err(|err| err.to_string())?;

    Ok(addrs)
}

type Multiaddrs = Vec<Multiaddr>;

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = "This is a rp2p-based program to sniff the topology of a libp2p network"
)]
struct Sniffier {
    /// The boostrap route table.
    #[arg(short, long, value_parser = clap_parse_multiaddr, default_value="/ip4/127.0.0.1/udp/4001/quic-v1")]
    bootstrap: Multiaddrs,

    /// Use verbose output
    #[arg(short, long, default_value_t = true)]
    verbose: bool,
}

fn main() {
    register_mio_network();
    register_mio_timer();
    register_futures_executor();

    if let Err(err) = block_on(sniffier()) {
        log::error!("Sniffier exit with error: {:#?}", err);
    }
}

async fn sniffier() -> io::Result<()> {
    let config = Sniffier::parse();

    let level = if config.verbose {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Info
    };

    pretty_env_logger::formatted_timed_builder()
        .filter_level(level)
        .init();

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    let switch = SwitchBuilder::new()
        .set_agent_version(&format!("rp2p-{}", VERSION))
        .host_key(MemoryHostKey::default())
        .route_table(MemoryRouteTable::default())
        .conn_pool(ConnPoolWithPing::default())
        .transport(TcpTransport::default())
        .transport(QuicTransport::default())
        .create()
        .await?;

    let peer_id = switch.public_key().await?.to_peer_id();

    log::info!("Start sniffer with host peer_id={}", peer_id);

    for raddr in config.bootstrap {
        log::info!("connect to peer: {}", raddr);
        switch.connect(&[raddr.clone()]).await?;

        log::info!("connect to peer: {} -- ok", raddr);
    }

    loop {
        sleep(Duration::from_secs(1)).await;
    }
}
