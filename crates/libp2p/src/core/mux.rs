//! libp2p is built on top of a stream abstraction and uses a bi-directional message stream to send data between peers.
//! However, relying on a single message stream over a connection between two peers can result in scalability issues
//! and bottlenecks. Each peer on either side of the connection may run multiple applications sending and waiting for
//! data over the stream. A single stream would block applications on one another, as one application would need to wait
//! for another to finish utilizing the stream before being able to send and receive its own messages.
//!
//! To overcome this issue, libp2p enables applications to employ stream multiplexing. Multiplexing allows for the creation
//! of multiple “virtual” connections within a single connection. This enables nodes to send multiple streams of messages
//! over separate virtual connections, providing a scalable solution that eliminates the bottleneck created by a single stream.
//! Then different applications/processes like Kademlia or GossipSub used by an application like IPFS would get their own stream
//! of data and make transmission more efficient. Stream multiplexing makes it so that applications or protocols running on top
//! of libp2p think that they’re the only ones running on that connection. Another example is when HTTP/2 introduced streams
//! into HTTP, allowing for many HTTP requests in parallel on the same connection.
//!
//! In summary, stream muxing can be used by applications on top of libp2p to share a single connection between various protocols,
//! providing a more efficient solution, particularly when establishing the connection is resource-intensive,
//! such as when NAT hole punching is necessary. By establishing a connection once and running multiple streams over the same connection,
//! libp2p can reduce the resource overhead and latency penalty associated with frequent connection establishment.
