#include <netdb.h>
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
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/noise/protocol_noise.h"
#include "protocol/ping/protocol_ping.h"
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
    if (redis_send(fd, cmd) != 0)
        return -1;
    char line[128];
    if (redis_read_line(fd, line, sizeof(line)) <= 0)
        return -1;
    return line[0] == ':' ? 0 : -1;
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

static int run_listener(const char *ip, const char *redis_host, const char *redis_port, int timeout, const char *muxer_name)
{
    multiaddr_t *addr = NULL;
    char ma_str[64];
    snprintf(ma_str, sizeof(ma_str), "/ip4/%s/tcp/0", ip);
    addr = multiaddr_new_from_str(ma_str, NULL);
    if (!addr)
        return 1;
    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&tcfg);
    libp2p_listener_t *lst = NULL;
    if (libp2p_transport_listen(tcp, addr, &lst) != 0)
    {
        multiaddr_free(addr);
        return 1;
    }
    multiaddr_free(addr);
    multiaddr_t *bound = NULL;
    if (libp2p_listener_local_addr(lst, &bound) != 0)
    {
        return 1;
    }
    int ma_err = 0;
    char *bound_str = multiaddr_to_str(bound, &ma_err);
    if (!bound_str || ma_err != 0)
    {
        multiaddr_free(bound);
        return 1;
    }
    int rfd = redis_connect(redis_host, redis_port);
    if (rfd < 0)
    {
        fprintf(stderr, "listener failed to connect to redis\n");
        free(bound_str);
        return 1;
    }
    int rc = redis_rpush(rfd, "listenerAddr", bound_str);
    close(rfd);
    free(bound_str);
    multiaddr_free(bound);
    if (rc != 0)
        return 1;
    libp2p_conn_t *raw = NULL;
    if (libp2p_listener_accept(lst, &raw) != 0)
    {
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        return 1;
    }
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
    if (libp2p_upgrader_upgrade_inbound(up, raw, &uconn) != LIBP2P_UPGRADER_OK)
    {
        fprintf(stderr, "listener upgrade failed\n");
        libp2p_upgrader_free(up);
        libp2p_muxer_free(muxer);
        libp2p_security_free(noise);
        libp2p_listener_close(lst);
        libp2p_listener_free(lst);
        libp2p_transport_free(tcp);
        return 1;
    }
    libp2p_ping_serve(uconn->conn);
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
    int rfd = redis_connect(redis_host, redis_port);
    if (rfd < 0)
    {
        fprintf(stderr, "dialer failed to connect to redis\n");
        return 1;
    }
    char *addr_str = redis_blpop(rfd, "listenerAddr", timeout);
    close(rfd);
    if (!addr_str)
    {
        fprintf(stderr, "dialer failed to get listener address from redis\n");
        return 1;
    }
    int err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    free(addr_str);
    if (!addr || err)
        return 1;
    libp2p_tcp_config_t tcfg = libp2p_tcp_config_default();
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&tcfg);
    libp2p_conn_t *raw = NULL;
    uint64_t start = now_mono_ms();
    if (libp2p_transport_dial(tcp, addr, &raw) != 0)
    {
        fprintf(stderr, "transport dial failed\n");
        multiaddr_free(addr);
        libp2p_transport_free(tcp);
        return 1;
    }
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
    // Record ping RTT
    uint64_t ping_start = now_mono_ms();
    uint64_t ping_ms = 0;
    if (libp2p_ping_roundtrip(uconn->conn, timeout * 1000, &ping_ms) != LIBP2P_PING_OK)
    {
        fprintf(stderr, "ping failed\n");
        libp2p_conn_close(uconn->conn);
        free(uconn);
        libp2p_upgrader_free(up);
        libp2p_muxer_free(muxer);
        libp2p_security_free(noise);
        multiaddr_free(addr);
        libp2p_transport_free(tcp);
        return 1;
    }

    // Calculate handshake + one RTT duration
    uint64_t handshake_plus_rtt_ms = now_mono_ms() - start;

    // Output JSON to stdout (as per spec)
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
    const char *transport = getenv("transport");
    if (!transport || strcmp(transport, "tcp") != 0)
    {
        fprintf(stderr, "unsupported transport\n");
        return 1;
    }
    const char *muxer = getenv("muxer");
    if (!muxer || (strcmp(muxer, "yamux") != 0 && strcmp(muxer, "mplex") != 0))
    {
        fprintf(stderr, "unsupported muxer (supported: yamux, mplex)\n");
        return 1;
    }
    const char *sec = getenv("security");
    if (!sec || strcmp(sec, "noise") != 0)
    {
        fprintf(stderr, "unsupported security\n");
        return 1;
    }
    int is_dialer = getenv("is_dialer") && strcmp(getenv("is_dialer"), "true") == 0;
    const char *ip = getenv("ip");
    if (!ip)
        ip = "0.0.0.0";
    const char *redis_addr = getenv("redis_addr");
    if (!redis_addr)
        redis_addr = "redis:6379"; // Default to Docker service name
    int timeout = getenv("test_timeout_seconds") ? atoi(getenv("test_timeout_seconds")) : 180;
    char host[64] = "", port[16] = "";
    sscanf(redis_addr, "%63[^:]:%15s", host, port);
    if (!*port)
        strcpy(port, "6379");
    if (is_dialer)
        return run_dialer(host, port, timeout, muxer);
    else
        return run_listener(ip, host, port, timeout, muxer);
}