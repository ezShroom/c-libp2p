#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <noise/protocol/randstate.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "peer_id/peer_id_ed25519.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/ping/protocol_ping.h"
#include "protocol/protocol_handler.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/yamux/protocol_yamux.h"
#include "transport/transport.h"
#include "transport/upgrader.h"

#ifndef NOW_MONO_MS_DECLARED
static inline uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}
#endif

static int redis_connect(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0)
    {
        freeaddrinfo(res);
        return -1;
    }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0)
    {
        freeaddrinfo(res);
        close(fd);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int redis_send(int fd, const char *cmd)
{
    size_t len = strlen(cmd);
    const char *p = cmd;
    ssize_t n;
    while (len)
    {
        n = send(fd, p, len, 0);
        if (n <= 0)
            return -1;
        p += n;
        len -= n;
    }
    return 0;
}

static int redis_read_line(int fd, char *buf, size_t max)
{
    size_t pos = 0;
    char c;
    while (pos + 1 < max)
    {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0)
            return -1;
        buf[pos++] = c;
        if (c == '\n')
            break;
    }
    buf[pos] = 0;
    return (int)pos;
}

static int redis_rpush(int fd, const char *key, const char *val)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "*3\r\n$5\r\nRPUSH\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n", strlen(key), key, strlen(val), val);
    fprintf(stderr, "DEBUG: Redis RPUSH command: %s", cmd);
    if (redis_send(fd, cmd) != 0)
    {
        fprintf(stderr, "DEBUG: redis_send failed\n");
        return -1;
    }
    char line[128];
    int bytes_read = redis_read_line(fd, line, sizeof(line));
    fprintf(stderr, "DEBUG: Redis response: bytes_read=%d, line=%s\n", bytes_read, bytes_read > 0 ? line : "NULL");
    if (bytes_read <= 0)
    {
        fprintf(stderr, "DEBUG: redis_read_line failed\n");
        return -1;
    }
    int result = line[0] == ':' ? 0 : -1;
    fprintf(stderr, "DEBUG: Redis RPUSH result: %d (line[0]='%c')\n", result, line[0]);
    return result;
}

static char *redis_blpop(int fd, const char *key, int timeout_sec)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "*3\r\n$5\r\nBLPOP\r\n$%zu\r\n%s\r\n$%d\r\n%d\r\n", strlen(key), key, (int)snprintf(NULL, 0, "%d", timeout_sec),
             timeout_sec);
    if (redis_send(fd, cmd) != 0)
        return NULL;
    char line[256];
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL;
    if (line[0] != '*')
        return NULL;
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL; // key bulk
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL; // key value
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return NULL;          // value bulk header
    int len = atoi(line + 1); // skip '$'
    char *val = malloc((size_t)len + 1);
    if (!val)
        return NULL;
    size_t got = 0;
    while (got < (size_t)len)
    {
        ssize_t n = recv(fd, val + got, len - got, 0);
        if (n <= 0)
        {
            free(val);
            return NULL;
        }
        got += n;
    }
    val[len] = 0;
    recv(fd, line, 2, 0); // consume CRLF
    return val;
}

static void gen_keys(uint8_t *priv, size_t len) { noise_randstate_generate_simple(priv, len); }

static libp2p_muxer_t *create_muxer(const char *muxer_name)
{
    if (strcmp(muxer_name, "yamux") == 0)
        return libp2p_yamux_new();
    else if (strcmp(muxer_name, "mplex") == 0)
        return libp2p_mplex_new();
    else
        return NULL;
}

/* File-scope handler that responds to identify requests */
static int identify_stream_handler(libp2p_stream_t *stream, void *user_data)
{
    fprintf(stderr, "identify_stream_handler: got new stream\n");
    (void)user_data;

    // For identify protocol, we just need to receive the identify request
    // and send back our own identify information. For interop tests, we can
    // send a minimal response or close the stream.

    uint8_t buf[1024];
    ssize_t n = libp2p_stream_read(stream, buf, sizeof(buf));

    if (n > 0)
    {
        fprintf(stderr, "identify_stream_handler: received %zd bytes\n", n);
        // Send minimal identify response (for interop we just close)
    }
    else if (n == -5)
    {
        // EAGAIN - no data yet, that's fine for identify
        fprintf(stderr, "identify_stream_handler: no data available yet\n");
    }
    else
    {
        fprintf(stderr, "identify_stream_handler: read error %zd\n", n);
    }

    libp2p_stream_close(stream);
    fprintf(stderr, "identify_stream_handler: done\n");
    return 0;
}

/* Forward declaration for generic muxer types */
typedef enum
{
    MUXER_TYPE_MPLEX,
    MUXER_TYPE_YAMUX,
    MUXER_TYPE_UNKNOWN
} muxer_type_t;

typedef struct
{
    muxer_type_t type;
    union
    {
        libp2p_mplex_ctx_t *mplex;
        libp2p_yamux_ctx_t *yamux;
    } ctx;
} generic_muxer_ctx_t;

/* File-scope handler that echos 32-byte pings */
// Helper function to read exactly n bytes, similar to read_exact in Rust
static ssize_t stream_read_exact(libp2p_stream_t *stream, uint8_t *buf, size_t len)
{
    size_t total_read = 0;
    while (total_read < len)
    {
        ssize_t n = libp2p_stream_read(stream, buf + total_read, len - total_read);
        if (n > 0)
        {
            total_read += n;
        }
        else if (n == -5) // EAGAIN
        {
            // Data not available yet, wait a bit and try again
            usleep(1000); // 1ms
            continue;
        }
        else if (n == 0)
        {
            // EOF before reading all data
            return total_read;
        }
        else
        {
            // Other error
            return n;
        }
    }
    return total_read;
}

static int ping_stream_handler(libp2p_stream_t *stream, void *user_data)
{
    fprintf(stderr, "ping_stream_handler: got new stream\n");
    (void)user_data;

    // Simple ping echo server - wait for 32 bytes, then echo them back
    uint8_t payload[32];
    size_t total_read = 0;

    // Read exactly 32 bytes, handling partial reads and waiting for data
    while (total_read < 32)
    {
        ssize_t bytes_read = libp2p_stream_read(stream, payload + total_read, 32 - total_read);

        if (bytes_read > 0)
        {
            total_read += bytes_read;
            fprintf(stderr, "ping_stream_handler: read %zd bytes (total: %zu/32)\n", bytes_read, total_read);
        }
        else if (bytes_read == 0)
        {
            // EOF - stream closed
            fprintf(stderr, "ping_stream_handler: stream closed by peer\n");
            return -1;
        }
        else
        {
            // Error or would block - wait a bit and try again
            // This handles the case where yamux data frame hasn't arrived yet
            struct timespec ts = {0, 10000000}; // 10ms
            nanosleep(&ts, NULL);
        }
    }

    fprintf(stderr, "ping_stream_handler: received complete 32-byte ping payload\n");

    // Echo the payload back
    ssize_t bytes_written = libp2p_stream_write(stream, payload, 32);
    if (bytes_written != 32)
    {
        fprintf(stderr, "ping_stream_handler: failed to write ping response\n");
        return -1;
    }

    fprintf(stderr, "ping_stream_handler: successfully echoed ping payload\n");

    // Keep the stream open for potential additional pings
    return 0;
}

static int run_listener(const char *ip, const char *redis_host, const char *redis_port, int timeout, const char *muxer_name)
{
    fprintf(stderr, "DEBUG: run_listener started with ip=%s, redis_host=%s, redis_port=%s, timeout=%d, muxer=%s\n", ip, redis_host, redis_port,
            timeout, muxer_name);

    multiaddr_t *addr = NULL;
    char ma_str[64];
    snprintf(ma_str, sizeof(ma_str), "/ip4/%s/tcp/0", ip);
    fprintf(stderr, "DEBUG: Creating multiaddr: %s\n", ma_str);
    addr = multiaddr_new_from_str(ma_str, NULL);
    if (!addr)
    {
        fprintf(stderr, "DEBUG: Failed to create multiaddr\n");
        return 1;
    }
    fprintf(stderr, "DEBUG: Created multiaddr successfully\n");

    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&tcfg);
    fprintf(stderr, "DEBUG: Created TCP transport\n");

    libp2p_listener_t *lst = NULL;
    fprintf(stderr, "DEBUG: Starting to listen...\n");
    if (libp2p_transport_listen(tcp, addr, &lst) != 0)
    {
        fprintf(stderr, "DEBUG: Failed to listen\n");
        multiaddr_free(addr);
        return 1;
    }
    fprintf(stderr, "DEBUG: Listen successful\n");
    multiaddr_free(addr);

    multiaddr_t *bound = NULL;
    fprintf(stderr, "DEBUG: Getting local address...\n");
    if (libp2p_listener_local_addr(lst, &bound) != 0)
    {
        fprintf(stderr, "DEBUG: Failed to get local address\n");
        return 1;
    }
    fprintf(stderr, "DEBUG: Got local address\n");

    int ma_err = 0;
    char *bound_str = multiaddr_to_str(bound, &ma_err);
    if (!bound_str || ma_err != 0)
    {
        fprintf(stderr, "DEBUG: Failed to convert address to string\n");
        multiaddr_free(bound);
        return 1;
    }
    fprintf(stderr, "DEBUG: Bound address: %s\n", bound_str);

    // Replace 0.0.0.0 with actual container IP for publishing
    char *publish_str = bound_str;
    char actual_addr[256];
    if (strstr(bound_str, "0.0.0.0"))
    {
        // Get the tcp/port from the bound address (/ip4/0.0.0.0/tcp/40515 -> /tcp/40515)
        char *tcp_start = strstr(bound_str, "/tcp/");
        if (tcp_start)
        {
            // Get container IP by connecting to an external address and checking local socket
            int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (test_sock >= 0)
            {
                struct sockaddr_in test_addr;
                test_addr.sin_family = AF_INET;
                test_addr.sin_port = htons(80);
                inet_pton(AF_INET, "8.8.8.8", &test_addr.sin_addr);

                if (connect(test_sock, (struct sockaddr *)&test_addr, sizeof(test_addr)) == 0)
                {
                    struct sockaddr_in local_addr;
                    socklen_t len = sizeof(local_addr);
                    if (getsockname(test_sock, (struct sockaddr *)&local_addr, &len) == 0)
                    {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &local_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                        snprintf(actual_addr, sizeof(actual_addr), "/ip4/%s%s", ip_str, tcp_start);
                        publish_str = actual_addr;
                        fprintf(stderr, "DEBUG: Replaced 0.0.0.0 with actual IP: %s\n", publish_str);
                    }
                }
                close(test_sock);
            }
        }
    }

    fprintf(stderr, "DEBUG: Connecting to Redis at %s:%s...\n", redis_host, redis_port);
    int rfd = redis_connect(redis_host, redis_port);
    if (rfd < 0)
    {
        fprintf(stderr, "listener failed to connect to redis\n");
        free(bound_str);
        return 1;
    }
    fprintf(stderr, "DEBUG: Connected to Redis successfully\n");

    fprintf(stderr, "DEBUG: Publishing address to Redis...\n");
    int rc = redis_rpush(rfd, "listenerAddr", publish_str);
    if (rc != 0)
    {
        fprintf(stderr, "DEBUG: Failed to publish address to Redis\n");
        close(rfd);
        free(bound_str);
        multiaddr_free(bound);
        return 1;
    }
    fprintf(stderr, "DEBUG: Published address to Redis successfully\n");
    close(rfd);
    free(bound_str);
    multiaddr_free(bound);

    libp2p_conn_t *raw = NULL;
    fprintf(stderr, "DEBUG: Waiting for incoming connection (this may hang)...\n");
    if (libp2p_listener_accept(lst, &raw) != 0)
    {
        fprintf(stderr, "DEBUG: Accept failed\n");
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        return 1;
    }
    fprintf(stderr, "DEBUG: Accepted connection!\n");

    uint8_t static_key[32], id_key[32];
    gen_keys(static_key, 32);
    gen_keys(id_key, 32);
    libp2p_noise_config_t ncfg = {.static_private_key = static_key,
                                  .static_private_key_len = 32,
                                  .identity_private_key = id_key,
                                  .identity_private_key_len = 32,
                                  .identity_key_type = PEER_ID_ED25519_KEY_TYPE};
    libp2p_security_t *noise = libp2p_noise_security_new(&ncfg);
    libp2p_muxer_t *muxer = create_muxer(muxer_name);
    if (!muxer)
    {
        fprintf(stderr, "listener failed to create muxer: %s\n", muxer_name);
        libp2p_security_free(noise);
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        libp2p_transport_free(tcp);
        return 1;
    }
    const libp2p_security_t *sec[] = {noise, NULL};
    const libp2p_muxer_t *mux[] = {muxer, NULL};
    libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
    ucfg.security = sec;
    ucfg.n_security = 1;
    ucfg.muxers = mux;
    ucfg.n_muxers = 1;
    ucfg.handshake_timeout_ms = timeout * 1000;
    libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);
    libp2p_uconn_t *uconn = NULL;
    fprintf(stderr, "listener: starting inbound upgrade\n");
    libp2p_upgrader_err_t up_err = libp2p_upgrader_upgrade_inbound(up, raw, &uconn);
    fprintf(stderr, "listener: upgrade result = %d\n", up_err);
    if (up_err == LIBP2P_UPGRADER_OK)
    {
        fprintf(stderr, "listener: negotiated muxer = %s\n",
                (uconn->muxer == muxer) ? muxer_name : (strcmp(muxer_name, "yamux") == 0 ? "mplex" : "yamux"));
    }
    if (up_err != LIBP2P_UPGRADER_OK)
    {
        fprintf(stderr, "listener upgrade failed (err=%d)\n", up_err);
        libp2p_upgrader_free(up);
        libp2p_muxer_free(muxer);
        libp2p_security_free(noise);
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        libp2p_transport_free(tcp);
        return 1;
    }
    if (strcmp(muxer_name, "yamux") == 0)
    {
        /* -----------------------------------------------------------
         * Respond to ping requests over a negotiated stream using MPLEX.
         * ---------------------------------------------------------*/

        /* Create registry and register the ping handler */
        libp2p_protocol_handler_registry_t *registry = libp2p_protocol_handler_registry_new();
        libp2p_register_protocol_handler(registry, LIBP2P_PING_PROTO_ID, ping_stream_handler, NULL);
        libp2p_register_protocol_handler(registry, LIBP2P_IDENTIFY_PROTO_ID, identify_stream_handler, NULL);

        /* Start protocol handler in a background thread */
        libp2p_protocol_handler_ctx_t *phctx = libp2p_protocol_handler_ctx_new(registry, uconn);
        libp2p_protocol_handler_start(phctx);

        /* Give the dialer enough time to complete its single ping round-trip. */
        usleep(2 * 1000 * 1000); /* 2 s */

        /* Gracefully stop the handler thread and clean up. */
        libp2p_protocol_handler_stop(phctx);
        libp2p_protocol_handler_ctx_free(phctx);
        libp2p_protocol_handler_registry_free(registry);
    }
    else
    {
        /* Create registry and register the ping handler */
        libp2p_protocol_handler_registry_t *registry = libp2p_protocol_handler_registry_new();
        libp2p_register_protocol_handler(registry, LIBP2P_PING_PROTO_ID, ping_stream_handler, NULL);
        libp2p_register_protocol_handler(registry, LIBP2P_IDENTIFY_PROTO_ID, identify_stream_handler, NULL);

        /* Start protocol handler in a background thread */
        libp2p_protocol_handler_ctx_t *phctx = libp2p_protocol_handler_ctx_new(registry, uconn);
        libp2p_protocol_handler_start(phctx);

        /* Give the dialer enough time to complete its single ping round-trip. */
        usleep(2 * 1000 * 1000); /* 2 s */

        /* Gracefully stop the handler thread and clean up. */
        libp2p_protocol_handler_stop(phctx);
        libp2p_protocol_handler_ctx_free(phctx);
        libp2p_protocol_handler_registry_free(registry);
    }

    libp2p_conn_close(uconn->conn);
    free(uconn);
    libp2p_upgrader_free(up);
    libp2p_muxer_free(muxer);
    libp2p_security_free(noise);
    libp2p_listener_close(lst);
    libp2p_listener_free(lst);
    libp2p_transport_free(tcp);
    return 0;
}

static int run_dialer(const char *redis_host, const char *redis_port, int timeout, const char *muxer_name)
{
    fprintf(stderr, "DEBUG: run_dialer started with redis_host=%s, redis_port=%s, timeout=%d, muxer=%s\n", redis_host, redis_port, timeout,
            muxer_name);

    fprintf(stderr, "DEBUG: Connecting to Redis...\n");
    int rfd = redis_connect(redis_host, redis_port);
    if (rfd < 0)
    {
        fprintf(stderr, "dialer failed to connect to redis\n");
        return 1;
    }
    fprintf(stderr, "DEBUG: Connected to Redis successfully\n");

    fprintf(stderr, "DEBUG: Waiting for listener address from Redis (timeout=%d)...\n", timeout);
    char *addr_str = redis_blpop(rfd, "listenerAddr", timeout);
    close(rfd);
    if (!addr_str)
    {
        fprintf(stderr, "dialer failed to get listener address from redis\n");
        return 1;
    }
    fprintf(stderr, "DEBUG: Got listener address: %s\n", addr_str);

    int err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    free(addr_str);
    if (!addr || err)
    {
        fprintf(stderr, "DEBUG: Failed to parse multiaddr (err=%d)\n", err);
        return 1;
    }
    fprintf(stderr, "DEBUG: Parsed multiaddr successfully\n");

    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&tcfg);
    fprintf(stderr, "DEBUG: Created TCP transport\n");

    libp2p_conn_t *raw = NULL;
    uint64_t start = now_mono_ms();
    fprintf(stderr, "DEBUG: Attempting to dial...\n");
    if (libp2p_transport_dial(tcp, addr, &raw) != 0)
    {
        fprintf(stderr, "transport dial failed\n");
        multiaddr_free(addr);
        libp2p_transport_free(tcp);
        return 1;
    }
    fprintf(stderr, "DEBUG: Dial successful!\n");

    uint8_t static_key[32], id_key[32];
    gen_keys(static_key, 32);
    gen_keys(id_key, 32);
    libp2p_noise_config_t ncfg = {.static_private_key = static_key,
                                  .static_private_key_len = 32,
                                  .identity_private_key = id_key,
                                  .identity_private_key_len = 32,
                                  .identity_key_type = PEER_ID_ED25519_KEY_TYPE};
    libp2p_security_t *noise = libp2p_noise_security_new(&ncfg);
    libp2p_muxer_t *muxer = create_muxer(muxer_name);
    if (!muxer)
    {
        fprintf(stderr, "dialer failed to create muxer: %s\n", muxer_name);
        libp2p_security_free(noise);
        multiaddr_free(addr);
        libp2p_transport_free(tcp);
        return 1;
    }
    const libp2p_security_t *sec[] = {noise, NULL};
    const libp2p_muxer_t *mux[] = {muxer, NULL};
    libp2p_upgrader_config_t ucfg = libp2p_upgrader_config_default();
    ucfg.security = sec;
    ucfg.n_security = 1;
    ucfg.muxers = mux;
    ucfg.n_muxers = 1;
    ucfg.handshake_timeout_ms = timeout * 1000;
    libp2p_upgrader_t *up = libp2p_upgrader_new(&ucfg);
    libp2p_uconn_t *uconn = NULL;
    if (libp2p_upgrader_upgrade_outbound(up, raw, NULL, &uconn) != LIBP2P_UPGRADER_OK)
    {
        fprintf(stderr, "dialer upgrade failed\n");
        libp2p_upgrader_free(up);
        libp2p_muxer_free(muxer);
        libp2p_security_free(noise);
        multiaddr_free(addr);
        libp2p_transport_free(tcp);
        return 1;
    }
    fprintf(stderr, "dialer: negotiated muxer = %s\n", (uconn->muxer == muxer) ? muxer_name : (strcmp(muxer_name, "yamux") == 0 ? "mplex" : "yamux"));
    uint64_t ping_ms = 0;

    if (strcmp(muxer_name, "yamux") == 0)
    {
        /* Dialer now uses the generic ping stream path for all muxers */
        /* Open ping stream over negotiated connection (works for yamux & mplex) */
        libp2p_stream_t *ping_stream = NULL;
        if (libp2p_protocol_open_stream(uconn, LIBP2P_PING_PROTO_ID, &ping_stream) != LIBP2P_PROTOCOL_HANDLER_OK)
        {
            fprintf(stderr, "failed to open ping stream\n");
            // cleanup common path below
            libp2p_conn_close(uconn->conn);
            free(uconn);
            libp2p_upgrader_free(up);
            libp2p_muxer_free(muxer);
            libp2p_security_free(noise);
            multiaddr_free(addr);
            libp2p_transport_free(tcp);
            return 1;
        }

        uint8_t payload[32];
        noise_randstate_generate_simple(payload, sizeof(payload));

        uint64_t ping_start = now_mono_ms();

        if ((ssize_t)sizeof(payload) != libp2p_stream_write(ping_stream, payload, sizeof(payload)))
        {
            fprintf(stderr, "ping write failed\n");
            libp2p_stream_close(ping_stream);
            libp2p_stream_free(ping_stream);
            // cleanup
            libp2p_conn_close(uconn->conn);
            free(uconn);
            libp2p_upgrader_free(up);
            libp2p_muxer_free(muxer);
            libp2p_security_free(noise);
            multiaddr_free(addr);
            libp2p_transport_free(tcp);
            return 1;
        }

        uint8_t echo[32];
        ssize_t rcvd = stream_read_exact(ping_stream, echo, sizeof(echo));
        if (rcvd != (ssize_t)sizeof(echo) || memcmp(payload, echo, sizeof(echo)) != 0)
        {
            fprintf(stderr, "ping failed\n");
            libp2p_stream_close(ping_stream);
            libp2p_stream_free(ping_stream);
            // cleanup
            libp2p_conn_close(uconn->conn);
            free(uconn);
            libp2p_upgrader_free(up);
            libp2p_muxer_free(muxer);
            libp2p_security_free(noise);
            multiaddr_free(addr);
            libp2p_transport_free(tcp);
            return 1;
        }

        ping_ms = now_mono_ms() - ping_start;

        libp2p_stream_close(ping_stream);
        libp2p_stream_free(ping_stream);
    }
    else
    {
        /* Open ping stream over negotiated connection (works for yamux & mplex) */
        libp2p_stream_t *ping_stream = NULL;
        if (libp2p_protocol_open_stream(uconn, LIBP2P_PING_PROTO_ID, &ping_stream) != LIBP2P_PROTOCOL_HANDLER_OK)
        {
            fprintf(stderr, "failed to open ping stream\n");
            // cleanup common path below
            libp2p_conn_close(uconn->conn);
            free(uconn);
            libp2p_upgrader_free(up);
            libp2p_muxer_free(muxer);
            libp2p_security_free(noise);
            multiaddr_free(addr);
            libp2p_transport_free(tcp);
            return 1;
        }

        uint8_t payload[32];
        noise_randstate_generate_simple(payload, sizeof(payload));

        uint64_t ping_start = now_mono_ms();

        if ((ssize_t)sizeof(payload) != libp2p_stream_write(ping_stream, payload, sizeof(payload)))
        {
            fprintf(stderr, "ping write failed\n");
            libp2p_stream_close(ping_stream);
            libp2p_stream_free(ping_stream);
            // cleanup
            libp2p_conn_close(uconn->conn);
            free(uconn);
            libp2p_upgrader_free(up);
            libp2p_muxer_free(muxer);
            libp2p_security_free(noise);
            multiaddr_free(addr);
            libp2p_transport_free(tcp);
            return 1;
        }

        uint8_t echo[32];
        ssize_t rcvd = stream_read_exact(ping_stream, echo, sizeof(echo));
        if (rcvd != (ssize_t)sizeof(echo) || memcmp(payload, echo, sizeof(echo)) != 0)
        {
            fprintf(stderr, "ping failed\n");
            libp2p_stream_close(ping_stream);
            libp2p_stream_free(ping_stream);
            // cleanup
            libp2p_conn_close(uconn->conn);
            free(uconn);
            libp2p_upgrader_free(up);
            libp2p_muxer_free(muxer);
            libp2p_security_free(noise);
            multiaddr_free(addr);
            libp2p_transport_free(tcp);
            return 1;
        }

        ping_ms = now_mono_ms() - ping_start;

        libp2p_stream_close(ping_stream);
        libp2p_stream_free(ping_stream);
    }

    uint64_t handshake_plus_rtt_ms = now_mono_ms() - start;

    /* Output JSON to stdout (as per spec) */
    printf("{\"handshakePlusOneRTTMillis\":%.3f,\"pingRTTMilllis\":%.3f}\n", (double)handshake_plus_rtt_ms, (double)ping_ms);

    libp2p_conn_close(uconn->conn);
    free(uconn);
    libp2p_upgrader_free(up);
    libp2p_muxer_free(muxer);
    libp2p_security_free(noise);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
    return 0;
}

int main(void)
{
    fprintf(stderr, "DEBUG: Starting interop program\n");
    setvbuf(stderr, NULL, _IONBF, 0);
    const char *transport = getenv("transport");
    fprintf(stderr, "DEBUG: transport = %s\n", transport ? transport : "NULL");
    if (!transport || strcmp(transport, "tcp") != 0)
    {
        fprintf(stderr, "unsupported transport\n");
        return 1;
    }
    const char *muxer = getenv("muxer");
    fprintf(stderr, "DEBUG: muxer = %s\n", muxer ? muxer : "NULL");
    if (!muxer || (strcmp(muxer, "yamux") != 0 && strcmp(muxer, "mplex") != 0))
    {
        fprintf(stderr, "unsupported muxer (supported: yamux, mplex)\n");
        return 1;
    }
    const char *sec = getenv("security");
    fprintf(stderr, "DEBUG: security = %s\n", sec ? sec : "NULL");
    if (!sec || strcmp(sec, "noise") != 0)
    {
        fprintf(stderr, "unsupported security\n");
        return 1;
    }
    int is_dialer = getenv("is_dialer") && strcmp(getenv("is_dialer"), "true") == 0;
    fprintf(stderr, "DEBUG: is_dialer = %s\n", is_dialer ? "true" : "false");
    const char *ip = getenv("ip");
    if (!ip)
        ip = "0.0.0.0";
    fprintf(stderr, "DEBUG: ip = %s\n", ip);
    const char *redis_addr = getenv("redis_addr");
    if (!redis_addr)
        redis_addr = "redis:6379"; // Default to Docker service name
    fprintf(stderr, "DEBUG: redis_addr = %s\n", redis_addr);
    int timeout = getenv("test_timeout_seconds") ? atoi(getenv("test_timeout_seconds")) : 180;
    fprintf(stderr, "DEBUG: timeout = %d\n", timeout);
    char host[64] = "", port[16] = "";
    sscanf(redis_addr, "%63[^:]:%15s", host, port);
    if (!*port)
        strcpy(port, "6379");
    fprintf(stderr, "DEBUG: redis host = %s, port = %s\n", host, port);
    if (is_dialer)
    {
        fprintf(stderr, "DEBUG: Running as dialer\n");
        return run_dialer(host, port, timeout, muxer);
    }
    else
    {
        fprintf(stderr, "DEBUG: Running as listener\n");
        return run_listener(ip, host, port, timeout, muxer);
    }
}