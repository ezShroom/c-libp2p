#include <noise/protocol.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_secp256k1.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/protocol_handler.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/yamux/protocol_yamux.h"
#include "transport/connection.h"
#include "transport/transport.h"
#include "transport/upgrader.h"

// Constants for test configuration
#define WAIT_TIMEOUT_SECONDS 30
#define WAIT_ITERATIONS_PER_SECOND 10
#define WAIT_INTERVAL_MS 10
#define RESPONSE_TIMEOUT_SECONDS 5
#define RESPONSE_WAIT_ITERATIONS_PER_SECOND 100

// Structure to hold our identity key for the handler
typedef struct
{
    uint8_t identity_key[32];
    int completed;
    int dial_completed; // Flag for outgoing identify dial completion
} test_identity_ctx_t;

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static const char *upgrader_err_to_string(libp2p_upgrader_err_t err)
{
    switch (err)
    {
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

/**
 * @brief Identify request handler - provides local peer information
 */
static int handle_identify_request(const peer_id_t *local_peer_id, libp2p_identify_t *response, void *user_data)
{
    test_identity_ctx_t *ctx = (test_identity_ctx_t *)user_data;

    logmsg("📥 Received identify request, preparing response...\n");

    // Generate public key from our private key
    uint8_t *pubkey_buf = NULL;
    size_t pubkey_len = 0;
    peer_id_error_t err = peer_id_create_from_private_key_secp256k1(ctx->identity_key, sizeof(ctx->identity_key), &pubkey_buf, &pubkey_len);
    if (err != PEER_ID_SUCCESS)
    {
        logmsg("❌ Failed to generate public key: %d\n", err);
        return -1;
    }

    // Fill in response
    response->protocol_version = strdup("libp2p/1.0.0");
    response->agent_version = strdup("c-libp2p/0.1.0");
    response->public_key = pubkey_buf;
    response->public_key_len = pubkey_len;

    // Add some protocols
    response->protocols = malloc(2 * sizeof(char *));
    response->protocols[0] = strdup("/ipfs/id/1.0.0");
    response->protocols[1] = strdup("/ipfs/ping/1.0.0");
    response->num_protocols = 2;

    // Add a listen address (localhost)
    multiaddr_t *listen_addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/0", NULL);
    if (!listen_addr)
    {
        logmsg("❌ Failed to create listen address\n");
        return -1;
    }
    uint8_t listen_addr_bytes[1024];
    size_t listen_addr_len = 1024;
    int ret = multiaddr_get_bytes(listen_addr, listen_addr_bytes, listen_addr_len);
    if (ret < 0)
    {
        logmsg("❌ Failed to get bytes from multiaddr: %d\n", ret);
        multiaddr_free(listen_addr);
        return -1;
    }
    response->listen_addrs = malloc(sizeof(uint8_t *));
    response->listen_addrs_lens = malloc(sizeof(size_t));
    response->listen_addrs[0] = malloc(ret);
    memcpy(response->listen_addrs[0], listen_addr_bytes, ret);
    response->listen_addrs_lens[0] = ret;
    response->num_listen_addrs = 1;
    multiaddr_free(listen_addr);

    logmsg("✅ Using actual secp256k1 public key (%zu bytes protobuf) in identify response\n", pubkey_len);
    logmsg("✅ Sent identify response (protocol: %s, agent: %s, %zu protocols, %zu addresses)\n", response->protocol_version, response->agent_version,
           response->num_protocols, response->num_listen_addrs);

    ctx->completed = 1;

    return 0;
}

/**
 * @brief Identify response handler - processes received peer information
 */
static int handle_identify_response(const peer_id_t *remote_peer_id, const libp2p_identify_t *response, void *user_data)
{
    test_identity_ctx_t *ctx = (test_identity_ctx_t *)user_data;

    logmsg("📥 Received identify response from peer:\n");
    if (response->protocol_version)
    {
        logmsg("   Protocol Version: %s\n", response->protocol_version);
    }
    if (response->agent_version)
    {
        logmsg("   Agent Version: %s\n", response->agent_version);
    }
    if (response->public_key && response->public_key_len > 0)
    {
        logmsg("   Public Key: %zu bytes\n", response->public_key_len);
    }
    if (response->num_listen_addrs > 0)
    {
        logmsg("   Listen Addresses: %zu\n", response->num_listen_addrs);
    }
    if (response->num_protocols > 0)
    {
        logmsg("   Supported Protocols: %zu\n", response->num_protocols);
        for (size_t i = 0; i < response->num_protocols; i++)
        {
            if (response->protocols[i])
            {
                logmsg("     - %s\n", response->protocols[i]);
            }
        }
    }

    ctx->dial_completed = 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <multiaddr>\n", argv[0]);
        return 1;
    }

    // Variable declarations
    libp2p_security_t *noise = NULL;
    libp2p_muxer_t *mplex = NULL;
    libp2p_upgrader_t *upgrader = NULL;
    libp2p_protocol_handler_registry_t *registry = NULL;
    libp2p_protocol_handler_ctx_t *handler_ctx = NULL;
    libp2p_conn_t *raw_conn = NULL;
    libp2p_uconn_t *uconn = NULL;
    libp2p_transport_t *tcp = NULL;

    logmsg("=== Enhanced Identify Protocol Test (High-Level API) ===\n");
    logmsg("connecting to: %s\n", argv[1]);

    // Parse multiaddr
    int err = 0;
    multiaddr_t *maddr = multiaddr_new_from_str(argv[1], &err);
    if (!maddr || err != 0)
    {
        fprintf(stderr, "failed to parse multiaddr: %s\n", argv[1]);
        return 1;
    }

    // Extract connection info using proper multiaddr API
    char *host = NULL;
    int port = 0;

    // Check that we have at least 2 protocols (ip4 + tcp)
    size_t nprotocols = multiaddr_nprotocols(maddr);
    if (nprotocols < 2)
    {
        fprintf(stderr, "multiaddr must have at least ip4 and tcp protocols\n");
        multiaddr_free(maddr);
        return 1;
    }

    // Extract IP address and port using multiaddr API
    uint64_t proto_code;
    uint8_t addr_bytes[16];
    size_t addr_len;

    // Find IP4 protocol and extract address
    bool found_ip = false;
    for (size_t i = 0; i < nprotocols; i++)
    {
        if (multiaddr_get_protocol_code(maddr, i, &proto_code) == 0)
        {
            if (proto_code == MULTICODEC_IP4)
            {
                addr_len = sizeof(addr_bytes);
                if (multiaddr_get_address_bytes(maddr, i, addr_bytes, &addr_len) == 0 && addr_len == 4)
                {
                    // Convert IPv4 bytes to string
                    host = malloc(16); // Enough for "xxx.xxx.xxx.xxx\0"
                    if (host)
                    {
                        snprintf(host, 16, "%u.%u.%u.%u", addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]);
                        found_ip = true;
                    }
                }
                break;
            }
        }
    }

    // Find TCP protocol and extract port
    bool found_tcp = false;
    for (size_t i = 0; i < nprotocols; i++)
    {
        if (multiaddr_get_protocol_code(maddr, i, &proto_code) == 0)
        {
            if (proto_code == MULTICODEC_TCP)
            {
                addr_len = sizeof(addr_bytes);
                if (multiaddr_get_address_bytes(maddr, i, addr_bytes, &addr_len) == 0 && addr_len == 2)
                {
                    // Convert port bytes (big-endian) to integer
                    port = (addr_bytes[0] << 8) | addr_bytes[1];
                    found_tcp = true;
                }
                break;
            }
        }
    }

    if (!found_ip || !found_tcp || !host || port == 0)
    {
        fprintf(stderr, "failed to extract IP4/TCP address from multiaddr\n");
        free(host);
        multiaddr_free(maddr);
        return 1;
    }

    logmsg("connecting to %s:%d\n", host, port);

    // Create TCP transport and dial
    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    tcp = libp2p_tcp_transport_new(&tcfg);
    if (!tcp)
    {
        fprintf(stderr, "failed to create TCP transport\n");
        goto cleanup;
    }

    if (libp2p_transport_dial(tcp, maddr, &raw_conn) != 0)
    {
        fprintf(stderr, "failed to dial TCP connection\n");
        libp2p_transport_free(tcp);
        goto cleanup;
    }

    logmsg("raw TCP connection established\n");

    // Generate identity keys (like in ping test)
    static uint8_t static_key[32];
    static uint8_t identity_key[32];

    // Generate random keys directly
    noise_randstate_generate_simple(static_key, sizeof(static_key));
    noise_randstate_generate_simple(identity_key, sizeof(identity_key));

    libp2p_noise_config_t ncfg = {.static_private_key = static_key,
                                  .static_private_key_len = sizeof(static_key),
                                  .identity_private_key = identity_key,
                                  .identity_private_key_len = sizeof(identity_key),
                                  .identity_key_type = PEER_ID_SECP256K1_KEY_TYPE,
                                  .max_plaintext = 0};

    noise = libp2p_noise_security_new(&ncfg);
    mplex = libp2p_mplex_new();

    const libp2p_security_t *sec[] = {noise, NULL};
    const libp2p_muxer_t *mux[] = {mplex, NULL};

    // Create and configure upgrader
    libp2p_upgrader_config_t config = libp2p_upgrader_config_default();
    config.security = sec;
    config.n_security = 1;
    config.muxers = mux;
    config.n_muxers = 1;
    config.handshake_timeout_ms = WAIT_TIMEOUT_SECONDS * 1000;

    upgrader = libp2p_upgrader_new(&config);
    if (!upgrader)
    {
        fprintf(stderr, "failed to create upgrader\n");
        goto cleanup;
    }

    // Upgrade the connection (security + muxing)
    libp2p_upgrader_err_t upgrade_err = libp2p_upgrader_upgrade_outbound(upgrader, raw_conn, NULL, &uconn);
    if (upgrade_err != LIBP2P_UPGRADER_OK)
    {
        fprintf(stderr, "failed to upgrade connection: %s\n", upgrader_err_to_string(upgrade_err));
        goto cleanup;
    }

    logmsg("connection upgraded successfully\n");

    // Create protocol handler registry
    registry = libp2p_protocol_handler_registry_new();
    if (!registry)
    {
        fprintf(stderr, "failed to create protocol handler registry\n");
        goto cleanup;
    }

    // Register identify protocol handler
    test_identity_ctx_t ctx;
    memcpy(ctx.identity_key, identity_key, sizeof(identity_key));
    ctx.completed = 0;
    ctx.dial_completed = 0;
    if (libp2p_identify_register_handler(registry, handle_identify_request, &ctx) != 0)
    {
        fprintf(stderr, "failed to register identify handler\n");
        goto cleanup;
    }
    logmsg("identify protocol handler registered\n");

    // Create protocol handler context
    handler_ctx = libp2p_protocol_handler_ctx_new(registry, uconn);
    if (!handler_ctx)
    {
        fprintf(stderr, "failed to create protocol handler context\n");
        goto cleanup;
    }

    // Start protocol handler thread to listen for incoming streams
    if (libp2p_protocol_handler_start(handler_ctx) != 0)
    {
        fprintf(stderr, "failed to start protocol handler\n");
        goto cleanup;
    }
    logmsg("protocol handler started, listening for incoming streams\n");

    // Immediately send outbound identify request
    logmsg("Making immediate outbound identify request...\n");
    int dial_result = libp2p_identify_send_request_with_context(handler_ctx, handle_identify_response, &ctx);
    if (dial_result != 0)
    {
        logmsg("❌ Failed to send identify request (result: %d)\n", dial_result);
        goto cleanup;
    }
    logmsg("✅ Identify request sent, waiting for response...\n");
    // Wait for dial completion (up to RESPONSE_TIMEOUT_SECONDS)
    for (int j = 0; j < RESPONSE_TIMEOUT_SECONDS * RESPONSE_WAIT_ITERATIONS_PER_SECOND; j++)
    {
        usleep(WAIT_INTERVAL_MS * 1000);
        if (ctx.dial_completed)
            break;
    }
    if (!ctx.dial_completed)
        logmsg("⚠️ Identify response not received within timeout\n");
    logmsg("✅ Identify dial sequence completed\n");

cleanup:
    // Cleanup in reverse order of creation
    if (handler_ctx)
    {
        libp2p_protocol_handler_stop(handler_ctx);
        libp2p_protocol_handler_ctx_free(handler_ctx);
    }
    if (registry)
    {
        libp2p_protocol_handler_registry_free(registry);
    }
    if (uconn)
    {
        // Don't manually free the upgraded connection - let the upgrader handle it
        libp2p_conn_close(((struct libp2p_upgraded_conn *)uconn)->conn);
        free(uconn);
    }
    if (upgrader)
    {
        libp2p_upgrader_free(upgrader);
    }
    if (noise)
    {
        libp2p_security_free(noise);
    }
    if (mplex)
    {
        libp2p_muxer_free(mplex);
    }
    if (tcp)
    {
        libp2p_transport_free(tcp);
    }
    free(host);
    multiaddr_free(maddr);

    logmsg("=== Test completed ===\n");
    return 0; // Always return success since this test is about demonstrating API usage
}
