# Upgrading Connections

Transports produce raw, unencrypted `libp2p_conn_t` objects as described in [transports.md](transports.md). The upgrader composes a security protocol such as Noise with a stream multiplexer (mplex or yamux) to obtain a fully featured `libp2p_uconn_t`.

## Overview

1. Establish or accept a connection using a transport.
2. Select and configure the security protocol.
3. Choose a stream multiplexer.
4. Create the upgrader and upgrade the raw connection.

This guide details each step.

## Configuring Noise Security

The Noise protocol authenticates the remote peer and encrypts all bytes.
`libp2p_noise_config_t` exposes knobs for customizing the handshake:

- `static_private_key` – optional X25519 key to reuse across sessions.
- `identity_private_key` and `identity_key_type` – your node's identity keys.
- `early_data` and `extensions` – custom payloads exchanged during the handshake.
- `max_plaintext` – maximum size of plaintext chunks.

Most applications rely on `libp2p_noise_config_default()` which zeroes all fields.
When keys are omitted a new ephemeral key is generated and the identity key from
the peer ID will be used.

```c
#include "protocol/noise/protocol_noise.h"

libp2p_noise_config_t ncfg = libp2p_noise_config_default();
/* optionally provide your own keys here */
libp2p_security_t *noise = libp2p_noise_security_new(&ncfg);
```

The resulting object implements `libp2p_security_t` and can negotiate with a peer
over an existing transport connection.

## Choosing a Stream Multiplexer

libp2p-c offers the mplex and yamux multiplexers. They wrap the secure channel to
allow many independent streams.

```c
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/yamux/protocol_yamux.h"

libp2p_muxer_t *mplex = libp2p_mplex_new();    /* lightweight, simple */
libp2p_muxer_t *yamux = libp2p_yamux_new();    /* supports keepalive and window updates */
```

Both expose a unified `libp2p_muxer_t` interface. mplex is smaller and easier to
embed while yamux implements additional features such as ping frames and flow
control. Pick the one that best fits your application.

## Building the Upgrader

Once you have a security instance and at least one multiplexer, create the
upgrader. Multiple options can be supplied and will be negotiated using
multistream-select.

```c
#include "transport/upgrader.h"

const libp2p_security_t *security[] = { noise, NULL };
const libp2p_muxer_t    *muxers[]   = { yamux, mplex, NULL };

libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
ucfg.security  = security;  ucfg.n_security  = 1; /* Noise only          */
ucfg.muxers    = muxers;    ucfg.n_muxers    = 2; /* yamux preferred     */

libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);
```

The upgrader consumes a raw connection and returns a `libp2p_uconn_t` that holds
the secure channel, the negotiated multiplexer context and the authenticated
remote peer ID.

## Upgrading a Connection

Assuming you dialed a peer as shown in [transports.md](transports.md):

```c
libp2p_conn_t *raw = NULL;
if (libp2p_transport_dial(tcp, addr, &raw) != 0) {
    fprintf(stderr, "dial failed\n");
    return -1;
}

libp2p_uconn_t *uconn = NULL;
libp2p_upgrader_err_t upgrade_err = libp2p_upgrader_upgrade_outbound(upgrader, raw, NULL, &uconn);
if (upgrade_err != LIBP2P_UPGRADER_OK) {
    fprintf(stderr, "upgrade failed: %s\n", upgrader_err_to_string(upgrade_err));
    libp2p_conn_close(raw);
    return -1;
}

printf("connection upgraded successfully\n");
```

For inbound connections replace `upgrade_outbound` with
`libp2p_upgrader_upgrade_inbound`.

After success `uconn->conn` is encrypted and multiplexed. You may inspect
`uconn->remote_peer` to verify the peer's identity.

## Working with Protocols

The modern approach uses the protocol handler system instead of directly managing multiplexed streams. This provides automatic protocol negotiation, stream lifecycle management, and better error handling:

```c
#include "protocol/protocol_handler.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/ping/protocol_ping.h"

// Create protocol handler registry
libp2p_protocol_handler_registry_t *registry = libp2p_protocol_handler_registry_new();
if (!registry) {
    fprintf(stderr, "failed to create protocol handler registry\n");
    return -1;
}

// Register protocol handlers (example with identify)
typedef struct {
    uint8_t identity_key[32];
    int response_received;
} protocol_context_t;

protocol_context_t ctx;
// ... initialize ctx ...

if (libp2p_identify_register_handler(registry, my_identify_handler, &ctx) != 0) {
    fprintf(stderr, "failed to register identify handler\n");
    libp2p_protocol_handler_registry_free(registry);
    return -1;
}

// Create protocol handler context
libp2p_protocol_handler_ctx_t *handler_ctx = libp2p_protocol_handler_ctx_new(registry, uconn);
if (!handler_ctx) {
    fprintf(stderr, "failed to create protocol handler context\n");
    libp2p_protocol_handler_registry_free(registry);
    return -1;
}

// Start protocol handler (handles incoming streams automatically)
if (libp2p_protocol_handler_start(handler_ctx) != 0) {
    fprintf(stderr, "failed to start protocol handler\n");
    libp2p_protocol_handler_ctx_free(handler_ctx);
    libp2p_protocol_handler_registry_free(registry);
    return -1;
}

// Send requests using high-level API
if (libp2p_identify_send_request_with_context(handler_ctx, response_handler, &ctx) != 0) {
    fprintf(stderr, "failed to send identify request\n");
}

// The protocol handler automatically manages streams and handles responses
```

## Legacy: Direct Multiplexer Usage

**Note**: Direct multiplexer usage is considered legacy. Use the protocol handler system above for new code.

If you need direct access to streams for legacy code or custom protocols:

```c
// Legacy yamux usage (discouraged for new code)
libp2p_yamux_ctx_t *yx = libp2p_yamux_ctx_new(uconn->conn, 1, YAMUX_INITIAL_WINDOW);
uint32_t sid = 0;
if (libp2p_yamux_stream_open(yx, &sid) == 0) {
    libp2p_yamux_stream_send(yx, sid, (const uint8_t *)"hi", 2, LIBP2P_YAMUX_SYN);
}

// Legacy mplex usage (discouraged for new code)  
libp2p_mplex_ctx_t *mx = libp2p_mplex_ctx_new(uconn->conn);
uint64_t mplex_sid = 0;
if (libp2p_mplex_stream_open(mx, (const uint8_t *)"/my/protocol/1.0.0", 17, &mplex_sid) == 0) {
    // Use stream...
}
```

Processing incoming frames with legacy API:

```c
// Legacy event loop (use protocol handler system instead)
for (;;) {
    if (using_yamux) {
        libp2p_yamux_process_loop(yx);
    } else if (using_mplex) {
        libp2p_mplex_process_one(mx);
    }
}
```

## Error Handling

The modern upgrader API provides detailed error information:

```c
static const char *upgrader_err_to_string(libp2p_upgrader_err_t err) {
    switch (err) {
        case LIBP2P_UPGRADER_OK:
            return "OK";
        case LIBP2P_UPGRADER_ERR_NULL_PTR:
            return "NULL_PTR";
        case LIBP2P_UPGRADER_ERR_TIMEOUT:
            return "TIMEOUT";
        case LIBP2P_UPGRADER_ERR_SECURITY:
            return "SECURITY - No mutually supported security protocol";
        case LIBP2P_UPGRADER_ERR_MUXER:
            return "MUXER - No mutually supported muxer";
        default:
            return "UNKNOWN";
    }
}

// Use in upgrade calls
libp2p_upgrader_err_t err = libp2p_upgrader_upgrade_outbound(upgrader, raw, NULL, &uconn);
if (err != LIBP2P_UPGRADER_OK) {
    printf("Upgrade failed: %s\n", upgrader_err_to_string(err));
    // Handle specific error cases
}
```

## Closing

Remember to clean up resources in reverse order of creation:

```c
// Stop and cleanup protocol handlers first
if (handler_ctx) {
    libp2p_protocol_handler_stop(handler_ctx);
    libp2p_protocol_handler_ctx_free(handler_ctx);
}
if (registry) {
    libp2p_protocol_handler_registry_free(registry);
}

// Then cleanup connections and upgrader
if (uconn) {
    // Let the upgrader manage the upgraded connection lifecycle
    libp2p_conn_close(((struct libp2p_upgraded_conn *)uconn)->conn);
    free(uconn);
}
if (upgrader) {
    libp2p_upgrader_free(upgrader);
}

// Finally cleanup security and muxer instances
if (noise) {
    libp2p_security_free(noise);
}
if (yamux) {
    libp2p_muxer_free(yamux);
}
if (mplex) {
    libp2p_muxer_free(mplex);
}
```

This concludes the upgrade process. With secure multiplexed connections and the protocol handler system in place, you can implement higher level protocols such as ping, identify, or your own custom messaging schemes using the modern high-level API.

For a complete working example, see `examples/example_identify_dial.c` which demonstrates the API usage pattern.
