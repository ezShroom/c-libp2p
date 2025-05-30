# Example Dialer and Listener

The following example shows a small but complete program that establishes a TCP
connection to a remote peer and upgrades it with Noise security. Both the **yamux**
and **mplex** multiplexers are configured so that either can be negotiated. Once
upgraded, the dialer uses the modern protocol handler API to perform a ping round trip
and request the peer's identification information.

For an introduction to creating transports see
[transports.md](transports.md). The code below ties those pieces together using
the current high-level API.

## Dialer

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <noise/protocol.h>
#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/yamux/protocol_yamux.h"
#include "protocol/ping/protocol_ping.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/protocol_handler.h"
#include "transport/upgrader.h"
#include "peer_id/peer_id_secp256k1.h"

// Structure to hold context for protocol handlers
typedef struct {
    uint8_t identity_key[32];
    int completed;
    int dial_completed;
} test_context_t;

// Identify response handler
static int handle_identify_response(const peer_id_t *remote_peer_id, 
                                  const libp2p_identify_t *response, 
                                  void *user_data) {
    test_context_t *ctx = (test_context_t *)user_data;
    
    printf("✅ Received identify response:\n");
    printf("   Protocol Version: %s\n", response->protocol_version);
    printf("   Agent Version: %s\n", response->agent_version);
    printf("   Number of protocols: %zu\n", response->num_protocols);
    
    ctx->dial_completed = 1;
    return 0;
}

// Identify request handler (for serving incoming requests)
static int handle_identify_request(const peer_id_t *local_peer_id,
                                 libp2p_identify_t *response,
                                 void *user_data) {
    test_context_t *ctx = (test_context_t *)user_data;
    
    // Generate public key from private key
    uint8_t *pubkey_buf = NULL;
    size_t pubkey_len = 0;
    peer_id_error_t err = peer_id_create_from_private_key_secp256k1(
        ctx->identity_key, sizeof(ctx->identity_key), &pubkey_buf, &pubkey_len);
    if (err != PEER_ID_SUCCESS) {
        return -1;
    }
    
    // Fill in response
    response->protocol_version = strdup("libp2p/1.0.0");
    response->agent_version = strdup("c-libp2p/0.1.0");
    response->public_key = pubkey_buf;
    response->public_key_len = pubkey_len;
    
    // Add supported protocols
    response->protocols = malloc(2 * sizeof(char *));
    response->protocols[0] = strdup("/ipfs/id/1.0.0");
    response->protocols[1] = strdup("/ipfs/ping/1.0.0");
    response->num_protocols = 2;
    
    return 0;
}

int main(void)
{
    // Variable declarations for proper cleanup
    libp2p_security_t *noise = NULL;
    libp2p_muxer_t *yamux = NULL;
    libp2p_muxer_t *mplex = NULL;
    libp2p_upgrader_t *upgrader = NULL;
    libp2p_protocol_handler_registry_t *registry = NULL;
    libp2p_protocol_handler_ctx_t *handler_ctx = NULL;
    libp2p_conn_t *raw_conn = NULL;
    libp2p_uconn_t *uconn = NULL;
    
    // Parse multiaddr
    int err = 0;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4001", &err);
    if (!addr || err != 0) {
        fprintf(stderr, "failed to parse address\n");
        return 1;
    }

    // Create TCP transport and dial
    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&tcfg);
    if (!tcp) {
        fprintf(stderr, "failed to create TCP transport\n");
        goto cleanup;
    }

    if (libp2p_transport_dial(tcp, addr, &raw_conn) != 0) {
        fprintf(stderr, "dial failed\n");
        libp2p_transport_free(tcp);
        goto cleanup;
    }
    libp2p_transport_free(tcp); // Can free after dialing

    // Generate identity keys
    static uint8_t static_key[32];
    static uint8_t identity_key[32];
    noise_randstate_generate_simple(static_key, sizeof(static_key));
    noise_randstate_generate_simple(identity_key, sizeof(identity_key));

    // Configure Noise security
    libp2p_noise_config_t ncfg = {
        .static_private_key = static_key,
        .static_private_key_len = sizeof(static_key),
        .identity_private_key = identity_key,
        .identity_private_key_len = sizeof(identity_key),
        .identity_key_type = PEER_ID_SECP256K1_KEY_TYPE,
        .max_plaintext = 0
    };
    noise = libp2p_noise_security_new(&ncfg);

    // Create multiplexers
    yamux = libp2p_yamux_new();
    mplex = libp2p_mplex_new();

    // Configure upgrader
    const libp2p_security_t *security[] = { noise, NULL };
    const libp2p_muxer_t *muxers[] = { yamux, mplex, NULL };

    libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
    ucfg.security = security;
    ucfg.n_security = 1;
    ucfg.muxers = muxers;
    ucfg.n_muxers = 2;
    ucfg.handshake_timeout_ms = 30000;

    upgrader = libp2p_upgrader_new(&ucfg);
    if (!upgrader) {
        fprintf(stderr, "failed to create upgrader\n");
        goto cleanup;
    }

    // Upgrade the connection
    libp2p_upgrader_err_t upgrade_err = libp2p_upgrader_upgrade_outbound(upgrader, raw_conn, NULL, &uconn);
    if (upgrade_err != LIBP2P_UPGRADER_OK) {
        fprintf(stderr, "upgrade failed\n");
        goto cleanup;
    }

    printf("connection upgraded successfully\n");

    // Create protocol handler registry
    registry = libp2p_protocol_handler_registry_new();
    if (!registry) {
        fprintf(stderr, "failed to create protocol handler registry\n");
        goto cleanup;
    }

    // Set up context and register identify protocol handler
    test_context_t ctx;
    memcpy(ctx.identity_key, identity_key, sizeof(identity_key));
    ctx.completed = 0;
    ctx.dial_completed = 0;

    if (libp2p_identify_register_handler(registry, handle_identify_request, &ctx) != 0) {
        fprintf(stderr, "failed to register identify handler\n");
        goto cleanup;
    }

    // Create protocol handler context
    handler_ctx = libp2p_protocol_handler_ctx_new(registry, uconn);
    if (!handler_ctx) {
        fprintf(stderr, "failed to create protocol handler context\n");
        goto cleanup;
    }

    // Start protocol handler
    if (libp2p_protocol_handler_start(handler_ctx) != 0) {
        fprintf(stderr, "failed to start protocol handler\n");
        goto cleanup;
    }

    // Send identify request using high-level API
    printf("Sending identify request...\n");
    int dial_result = libp2p_identify_send_request_with_context(handler_ctx, handle_identify_response, &ctx);
    if (dial_result != 0) {
        printf("Failed to send identify request\n");
        goto cleanup;
    }

    // Wait for response (up to 5 seconds)
    for (int i = 0; i < 500; i++) {
        usleep(10000); // 10ms
        if (ctx.dial_completed) break;
    }

    if (!ctx.dial_completed) {
        printf("Identify response not received within timeout\n");
    }

cleanup:
    // Cleanup in reverse order
    if (handler_ctx) {
        libp2p_protocol_handler_stop(handler_ctx);
        libp2p_protocol_handler_ctx_free(handler_ctx);
    }
    if (registry) {
        libp2p_protocol_handler_registry_free(registry);
    }
    if (uconn) {
        libp2p_conn_close(((struct libp2p_upgraded_conn *)uconn)->conn);
        free(uconn);
    }
    if (upgrader) {
        libp2p_upgrader_free(upgrader);
    }
    if (noise) {
        libp2p_security_free(noise);
    }
    if (yamux) {
        libp2p_muxer_free(yamux);
    }
    if (mplex) {
        libp2p_muxer_free(mplex);
    }
    multiaddr_free(addr);
    return 0;
}
```

## Listener

The listening side accepts TCP connections, upgrades them in the same way and
then serves ping and identify requests using the protocol handler system.
For clarity the example handles a single inbound connection.

```c
#include <pthread.h>
#include <noise/protocol.h>
#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/yamux/protocol_yamux.h"
#include "protocol/ping/protocol_ping.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/protocol_handler.h"
#include "transport/upgrader.h"
#include "peer_id/peer_id_secp256k1.h"

typedef struct {
    uint8_t identity_key[32];
    multiaddr_t **listen_addrs;
    size_t num_listen_addrs;
    char **protocols;
    size_t num_protocols;
} listener_context_t;

// Identify request handler for the listener
static int listener_handle_identify_request(const peer_id_t *local_peer_id,
                                           libp2p_identify_t *response,
                                           void *user_data) {
    listener_context_t *ctx = (listener_context_t *)user_data;
    
    printf("📥 Received identify request from peer\n");
    
    // Generate public key from private key
    uint8_t *pubkey_buf = NULL;
    size_t pubkey_len = 0;
    peer_id_error_t err = peer_id_create_from_private_key_secp256k1(
        ctx->identity_key, sizeof(ctx->identity_key), &pubkey_buf, &pubkey_len);
    if (err != PEER_ID_SUCCESS) {
        return -1;
    }
    
    // Fill in response
    response->protocol_version = strdup("libp2p/1.0.0");
    response->agent_version = strdup("c-libp2p/0.1.0");
    response->public_key = pubkey_buf;
    response->public_key_len = pubkey_len;
    
    // Copy protocols
    response->protocols = malloc(ctx->num_protocols * sizeof(char *));
    for (size_t i = 0; i < ctx->num_protocols; i++) {
        response->protocols[i] = strdup(ctx->protocols[i]);
    }
    response->num_protocols = ctx->num_protocols;
    
    // Copy listen addresses
    response->listen_addrs = malloc(ctx->num_listen_addrs * sizeof(multiaddr_t *));
    for (size_t i = 0; i < ctx->num_listen_addrs; i++) {
        response->listen_addrs[i] = multiaddr_copy(ctx->listen_addrs[i]);
    }
    response->num_listen_addrs = ctx->num_listen_addrs;
    
    return 0;
}

int main(void)
{
    // Variable declarations
    libp2p_security_t *noise = NULL;
    libp2p_muxer_t *yamux = NULL;
    libp2p_muxer_t *mplex = NULL;
    libp2p_upgrader_t *upgrader = NULL;
    libp2p_protocol_handler_registry_t *registry = NULL;
    libp2p_protocol_handler_ctx_t *handler_ctx = NULL;
    libp2p_listener_t *listener = NULL;
    libp2p_conn_t *incoming = NULL;
    libp2p_uconn_t *client = NULL;
    
    int err;
    multiaddr_t *listen_addr = multiaddr_new_from_str("/ip4/0.0.0.0/tcp/4001", &err);
    if (!listen_addr || err != 0) {
        fprintf(stderr, "failed to parse listen address\n");
        return 1;
    }
    
    // Create TCP transport
    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&tcfg);
    if (!tcp) {
        fprintf(stderr, "failed to create TCP transport\n");
        goto cleanup;
    }

    // Generate identity keys
    static uint8_t static_key[32];
    static uint8_t identity_key[32];
    noise_randstate_generate_simple(static_key, sizeof(static_key));
    noise_randstate_generate_simple(identity_key, sizeof(identity_key));

    // Configure Noise security
    libp2p_noise_config_t ncfg = {
        .static_private_key = static_key,
        .static_private_key_len = sizeof(static_key),
        .identity_private_key = identity_key,
        .identity_private_key_len = sizeof(identity_key),
        .identity_key_type = PEER_ID_SECP256K1_KEY_TYPE,
        .max_plaintext = 0
    };
    noise = libp2p_noise_security_new(&ncfg);

    // Create multiplexers
    yamux = libp2p_yamux_new();
    mplex = libp2p_mplex_new();

    // Configure upgrader
    const libp2p_security_t *security[] = { noise, NULL };
    const libp2p_muxer_t *muxers[] = { yamux, mplex, NULL };

    libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
    ucfg.security = security;
    ucfg.n_security = 1;
    ucfg.muxers = muxers;
    ucfg.n_muxers = 2;

    upgrader = libp2p_upgrader_new(&ucfg);
    if (!upgrader) {
        fprintf(stderr, "failed to create upgrader\n");
        goto cleanup;
    }

    // Start listening
    if (libp2p_transport_listen(tcp, listen_addr, &listener) != 0) {
        fprintf(stderr, "listen failed\n");
        goto cleanup;
    }

    printf("Listening on %s\n", multiaddr_string(listen_addr));

    // Set up listener context
    listener_context_t ctx;
    memcpy(ctx.identity_key, identity_key, sizeof(identity_key));
    
    // Set up supported protocols
    static char *protocols[] = { "/ipfs/id/1.0.0", "/ipfs/ping/1.0.0" };
    ctx.protocols = protocols;
    ctx.num_protocols = 2;
    
    // Set up listen addresses
    static multiaddr_t *listen_addrs[] = { NULL };
    listen_addrs[0] = listen_addr;
    ctx.listen_addrs = listen_addrs;
    ctx.num_listen_addrs = 1;

    // Accept incoming connection
    if (libp2p_listener_accept(listener, &incoming) == 0) {
        printf("Accepted incoming connection\n");
        
        // Upgrade the connection
        libp2p_upgrader_err_t upgrade_err = libp2p_upgrader_upgrade_inbound(upgrader, incoming, &client);
        if (upgrade_err != LIBP2P_UPGRADER_OK) {
            fprintf(stderr, "failed to upgrade inbound connection\n");
            goto cleanup;
        }

        // Create protocol handler registry and register handlers
        registry = libp2p_protocol_handler_registry_new();
        if (!registry) {
            fprintf(stderr, "failed to create protocol handler registry\n");
            goto cleanup;
        }

        if (libp2p_identify_register_handler(registry, listener_handle_identify_request, &ctx) != 0) {
            fprintf(stderr, "failed to register identify handler\n");
            goto cleanup;
        }

        // Create and start protocol handler
        handler_ctx = libp2p_protocol_handler_ctx_new(registry, client);
        if (!handler_ctx) {
            fprintf(stderr, "failed to create protocol handler context\n");
            goto cleanup;
        }

        if (libp2p_protocol_handler_start(handler_ctx) != 0) {
            fprintf(stderr, "failed to start protocol handler\n");
            goto cleanup;
        }

        printf("Protocol handler started, ready to serve requests\n");
        
        // Keep serving for a while (in production, you'd loop and accept multiple peers)
        sleep(30);
    }

cleanup:
    // Cleanup in reverse order
    if (handler_ctx) {
        libp2p_protocol_handler_stop(handler_ctx);
        libp2p_protocol_handler_ctx_free(handler_ctx);
    }
    if (registry) {
        libp2p_protocol_handler_registry_free(registry);
    }
    if (client) {
        libp2p_conn_close(((struct libp2p_upgraded_conn *)client)->conn);
        free(client);
    }
    if (listener) {
        libp2p_listener_close(listener);
        libp2p_listener_free(listener);
    }
    if (upgrader) {
        libp2p_upgrader_free(upgrader);
    }
    if (noise) {
        libp2p_security_free(noise);
    }
    if (yamux) {
        libp2p_muxer_free(yamux);
    }
    if (mplex) {
        libp2p_muxer_free(mplex);
    }
    if (tcp) {
        libp2p_transport_free(tcp);
    }
    multiaddr_free(listen_addr);
    return 0;
}
```

These examples demonstrate the modern protocol handler API which provides:

- **Protocol Handler Registry**: Centralized registration of protocol handlers
- **Protocol Handler Context**: Manages protocol instances and stream handling
- **High-level API Functions**: Like `libp2p_identify_send_request_with_context()` and `libp2p_identify_register_handler()`
- **Proper Resource Management**: Structured cleanup with proper error handling
- **Modern Configuration**: Current upgrader and security configuration patterns

Consult the tests under `tests/` and the working example in `examples/example_identify_dial.c` for more production-like code and refer back to [transports.md](transports.md) for a deeper explanation of the transport API.
