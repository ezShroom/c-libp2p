# Ping Protocol

The ping protocol verifies connectivity between two libp2p nodes and measures the round-trip latency. It runs over an existing libp2p connection that has already been upgraded to use security and multiplexing as described in [upgrading.md](upgrading.md).

## Pinging a Remote Peer

After obtaining a `libp2p_uconn_t` from the upgrader you can initiate a ping. The helper opens a new stream using the configured multiplexer, performs a single ping exchange and returns the measured RTT in milliseconds.

```c
#include "protocol/noise/protocol_noise.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/ping/protocol_ping.h"
#include "transport/upgrader.h"

/* upgrade a raw connection using Noise and mplex */
libp2p_noise_config_t ncfg = libp2p_noise_config_default();
libp2p_security_t *noise = libp2p_noise_security_new(&ncfg);
libp2p_muxer_t *mux = libp2p_mplex_new();
const libp2p_security_t *sec[] = { noise, NULL };
const libp2p_muxer_t *muxers[] = { mux, NULL };
libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
ucfg.security = sec; ucfg.n_security = 1;
ucfg.muxers = muxers; ucfg.n_muxers = 1;
libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);

libp2p_uconn_t *uconn = NULL;
libp2p_upgrader_upgrade_outbound(up, conn, my_id, &uconn);

uint64_t rtt = 0;
libp2p_ping_roundtrip(uconn->conn, 1000, &rtt);
```

The ping call blocks until either the round-trip completes or the timeout elapses. On success `rtt` contains the latency in milliseconds.

## Serving Ping Requests

Servers should dedicate a thread to handle incoming ping streams. The `libp2p_ping_serve` function expects the multiplexed connection obtained from the upgrader. It reads ping messages in a loop and echoes them back to the remote peer.

```c
void *ping_worker(void *arg)
{
    libp2p_uconn_t *u = arg;
    libp2p_ping_serve(u->conn);
    return NULL;
}
```

Launch the worker after upgrading an inbound connection so that peers can probe your node's reachability.

## Protocol Details

A ping message consists of 32 random bytes sent on the stream identified by `"/ipfs/ping/1.0.0"`. The responder echoes the payload verbatim. Multiple ping exchanges may occur sequentially on the same stream. For complete semantics refer to the [ping specification](../specs/ping/ping.md).
