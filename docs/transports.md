# Transports

Transports establish the byte streams on top of which every other libp2p feature operates. Once you have generated a peer identity as shown in [peer-id.md](peer-id.md) and constructed the appropriate [multiaddress](multiaddress.md), a transport is responsible for turning that address into an active connection. The API exposes helpers for dialing remote peers as well as listening for inbound connections.

A transport implementation adheres to the `libp2p_transport_t` interface. The library currently includes a production ready TCP transport and leaves room for custom implementations (for example QUIC or Bluetooth) to be plugged in by the application.

## Creating the TCP Transport

```c
#include "protocol/tcp/protocol_tcp.h"

libp2p_tcp_config_t cfg = libp2p_tcp_config_default();
libp2p_transport_t *tcp = libp2p_tcp_transport_new(&cfg);
```

`libp2p_tcp_config_default()` fills the configuration structure with sensible defaults. The fields allow you to tune socket options such as `SO_REUSEADDR`, backlog size and connection timeouts. The transport object returned by `libp2p_tcp_transport_new()` can then be used for both dialing and listening.

## Dialing a Remote Peer

To open a connection supply a multiaddress describing the target and an optional timeout. After the function returns a `libp2p_conn_t` represents the raw socket.

```c
#include "multiformats/multiaddr/multiaddr.h"

/* assume `addr` is built as described in multiaddress.md */
libp2p_conn_t *conn = NULL;
int err = libp2p_transport_dial(tcp, addr, &conn);
if (err != 0) {
    /* handle failure to connect */
}
```

The returned connection is not yet secured or multiplexed. To upgrade it see [upgrading.md](upgrading.md). On success you may query `conn->remote_ma` to obtain the canonical multiaddress of the remote end.

## Listening for Incoming Connections

A listener binds to the given multiaddress and waits for peers to dial it. Once a peer connects you obtain a `libp2p_conn_t` in the same way as with `dial`.

```c
libp2p_listener_t *lst = NULL;
int err = libp2p_transport_listen(tcp, addr, &lst);
if (err != 0) {
    /* handle bind failure */
}

for (;;) {
    libp2p_conn_t *incoming = NULL;
    if (libp2p_listener_accept(lst, &incoming) == 0) {
        /* process incoming connection */
    }
}
```

When accepting connections you typically immediately hand them over to the upgrader which performs security and multiplexing.

## Using Peer IDs with Transports

While transports themselves operate purely on byte streams they are closely tied to peer identities. After establishing a connection the upgrader uses the underlying transport to negotiate and verify the remote peer's ID. The example below sketches the full flow after creating a peer ID and multiaddress:

```c
#include "peer_id/peer_id.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/mplex/protocol_mplex.h"
#include "transport/upgrader.h"

/* assume `my_id` contains our local peer ID */
/* assume `addr` contains the remote multiaddress */

libp2p_conn_t *raw = NULL;
libp2p_transport_dial(tcp, addr, &raw);

libp2p_noise_config_t ncfg = libp2p_noise_config_default();
libp2p_security_t *noise = libp2p_noise_security_new(&ncfg);
libp2p_muxer_t *mux = libp2p_mplex_new();

const libp2p_security_t *sec[] = { noise, NULL };
const libp2p_muxer_t *muxes[] = { mux, NULL };
libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
ucfg.security = sec; ucfg.n_security = 1;
ucfg.muxers = muxes; ucfg.n_muxers = 1;
libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);

libp2p_uconn_t *uconn = NULL;
libp2p_upgrader_upgrade_outbound(up, raw, my_id, &uconn);
```

The `upgrade_outbound` call performs the Noise handshake using the provided peer ID and yields an upgraded connection where `uconn->remote_peer` is the authenticated identity of the remote node. Streams can now be opened using the multiplexer just as shown in [examples.md](examples.md).

## Closing Connections

After finishing communication always close and free the associated objects:

```c
libp2p_conn_close(conn);
libp2p_conn_free(conn);
libp2p_transport_free(tcp);
```

The listener must also be closed and freed when no longer accepting peers.

## Implementing Custom Transports

New transports are created by filling out a `libp2p_transport_t` structure with function pointers for dialing, listening and closing connections. The TCP implementation serves as a reference. Custom transports should populate the `libp2p_conn_t` fields such as `local_ma` and `remote_ma` so that the rest of the stack can operate transparently.

All transports are responsible for returning connections that can be passed to the upgrader. Beyond that they remain agnostic of higher level protocols, making it possible to experiment with different network mediums without modifying the rest of the application.

