# Identify Protocol

The identify protocol exchanges peer metadata over an upgraded libp2p connection. After dialing or accepting a peer you can request their addresses, public key and supported protocols using the modern protocol handler API.

## Overview

The modern identify protocol implementation uses:

- **Protocol Handler Registry**: Centralized registration of identify handlers
- **Protocol Handler Context**: Manages identify protocol instances and stream handling  
- **High-level API Functions**: `libp2p_identify_send_request_with_context()` and `libp2p_identify_register_handler()`
- **Callback-based Design**: Response and request handlers are registered as callbacks

## Requesting Identification

First upgrade a raw connection as outlined in [upgrading.md](upgrading.md). Once you have a `libp2p_uconn_t`, create a protocol handler registry, register handlers, and use the high-level API to send identify requests:

```c
#include "protocol/identify/protocol_identify.h"
#include "protocol/protocol_handler.h"

// Context structure to hold state
typedef struct {
    uint8_t identity_key[32];
    int response_received;
} identify_context_t;

// Response handler callback
static int handle_identify_response(const peer_id_t *remote_peer_id,
                                  const libp2p_identify_t *response,
                                  void *user_data) {
    identify_context_t *ctx = (identify_context_t *)user_data;
    
    printf("Received identify response:\n");
    printf("  Protocol Version: %s\n", response->protocol_version);
    printf("  Agent Version: %s\n", response->agent_version);
    printf("  Number of protocols: %zu\n", response->num_protocols);
    
    // Process protocols
    for (size_t i = 0; i < response->num_protocols; i++) {
        printf("  Protocol[%zu]: %s\n", i, response->protocols[i]);
    }
    
    // Process listen addresses
    for (size_t i = 0; i < response->num_listen_addrs; i++) {
        char *addr_str = multiaddr_string(response->listen_addrs[i]);
        printf("  Listen Address[%zu]: %s\n", i, addr_str);
        free(addr_str);
    }
    
    ctx->response_received = 1;
    return 0;
}

// Request handler callback (for serving incoming requests)
static int handle_identify_request(const peer_id_t *local_peer_id,
                                 libp2p_identify_t *response,
                                 void *user_data) {
    identify_context_t *ctx = (identify_context_t *)user_data;
    
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

// Main function showing modern identify usage
int use_identify_protocol(libp2p_uconn_t *uconn) {
    // Create protocol handler registry
    libp2p_protocol_handler_registry_t *registry = libp2p_protocol_handler_registry_new();
    if (!registry) {
        return -1;
    }
    
    // Set up context
    identify_context_t ctx;
    // ... initialize identity_key ...
    ctx.response_received = 0;
    
    // Register identify protocol handler
    if (libp2p_identify_register_handler(registry, handle_identify_request, &ctx) != 0) {
        libp2p_protocol_handler_registry_free(registry);
        return -1;
    }
    
    // Create protocol handler context
    libp2p_protocol_handler_ctx_t *handler_ctx = libp2p_protocol_handler_ctx_new(registry, uconn);
    if (!handler_ctx) {
        libp2p_protocol_handler_registry_free(registry);
        return -1;
    }
    
    // Start protocol handler to listen for incoming streams
    if (libp2p_protocol_handler_start(handler_ctx) != 0) {
        libp2p_protocol_handler_ctx_free(handler_ctx);
        libp2p_protocol_handler_registry_free(registry);
        return -1;
    }
    
    // Send identify request using high-level API
    int result = libp2p_identify_send_request_with_context(handler_ctx, handle_identify_response, &ctx);
    if (result != 0) {
        printf("Failed to send identify request\n");
        goto cleanup;
    }
    
    // Wait for response (with timeout)
    for (int i = 0; i < 500; i++) {  // 5 second timeout
        usleep(10000); // 10ms
        if (ctx.response_received) break;
    }
    
    if (!ctx.response_received) {
        printf("No identify response received within timeout\n");
    }
    
cleanup:
    libp2p_protocol_handler_stop(handler_ctx);
    libp2p_protocol_handler_ctx_free(handler_ctx);
    libp2p_protocol_handler_registry_free(registry);
    return ctx.response_received ? 0 : -1;
}
```

## Listening for Identify Requests

The modern API automatically handles incoming identify requests through the registered handler. When you register an identify handler using `libp2p_identify_register_handler()`, it will automatically:

1. Listen for incoming streams on the `/ipfs/id/1.0.0` protocol
2. Call your handler callback when requests arrive
3. Send the response back to the requesting peer
4. Handle stream cleanup

Your handler callback just needs to populate the `libp2p_identify_t` response structure:

```c
static int my_identify_handler(const peer_id_t *local_peer_id,
                             libp2p_identify_t *response,
                             void *user_data) {
    // Fill in response fields
    response->protocol_version = strdup("libp2p/1.0.0");
    response->agent_version = strdup("my-app/1.0.0");
    
    // Add your public key, listen addresses, supported protocols etc.
    // The library handles encoding and sending the response
    
    return 0; // Success
}
```

## Using Identify Push

The identify push protocol (`/ipfs/id/push/1.0.0`) allows you to notify connected peers about changes to your peer information without them requesting it. This is useful when your listen addresses or supported protocols change.

```c
// Send an identify push notification
int send_identify_push(libp2p_protocol_handler_ctx_t *handler_ctx) {
    // The push functionality is typically integrated into the main identify handler
    // Check the current API for push-specific functions or use the general
    // identify request mechanism with appropriate protocol negotiation
    
    // Implementation depends on current API - check include/protocol/identify/protocol_identify.h
    return 0;
}
```

## Protocol Handler Lifecycle

The modern identify protocol follows this lifecycle:

1. **Create Registry**: `libp2p_protocol_handler_registry_new()`
2. **Register Handler**: `libp2p_identify_register_handler(registry, handler_callback, user_data)`
3. **Create Context**: `libp2p_protocol_handler_ctx_new(registry, uconn)`
4. **Start Handler**: `libp2p_protocol_handler_start(handler_ctx)`
5. **Send Requests**: `libp2p_identify_send_request_with_context(handler_ctx, response_callback, user_data)`
6. **Stop Handler**: `libp2p_protocol_handler_stop(handler_ctx)`
7. **Cleanup**: Free context and registry

## Error Handling

The modern API provides better error handling:

- Functions return specific error codes
- Callback functions can return error status
- Timeouts are handled automatically
- Resource cleanup is more predictable

```c
// Check return values
if (libp2p_identify_register_handler(registry, handler, ctx) != 0) {
    fprintf(stderr, "Failed to register identify handler\n");
    // Handle error
}

// Handle callback errors  
static int my_handler(const peer_id_t *peer_id, libp2p_identify_t *response, void *ctx) {
    if (some_error_condition) {
        return -1; // Signal error to the library
    }
    return 0; // Success
}
```

For a complete working example, see `examples/example_identify_dial.c` in the source tree. Consult the [identify specification](../specs/identify/README.md) for detailed message format and semantics.
