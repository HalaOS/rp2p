/// A switch is the context of all other libp2p objects.
///
/// This is the first thing you create when using libp2p.
/// Its primary use is to dail an outbound connection and accept newly incoming connection.
///
/// Creates a switch [`builder`](SwitchBuilder) by calling the function [`new`](Switch::new),
/// with this `builder`, the developer can control the configuration details of the `Switch`:
///
/// * configure the transport stack.
/// * configure the secure upgrader instance.
/// * configure the muxing upgrader instance.
/// * configure the connection pool for each peer.
pub struct Switch {}
