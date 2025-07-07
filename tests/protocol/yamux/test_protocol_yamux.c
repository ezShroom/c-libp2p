#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef _WIN32
#include "protocol/tcp/sys/socket.h"
#include <io.h>
#endif

#include "protocol/tcp/protocol_tcp.h"
#include "protocol/yamux/protocol_yamux.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

#define YAMUX_INITIAL_WINDOW (256 * 1024)

static libp2p_yamux_err_t g_dial_rc;
static libp2p_yamux_err_t g_listen_rc;
static libp2p_yamux_err_t g_loop_rc;

typedef struct
{
    int rfd;
    int wfd;
} pipe_ctx_t;

static ssize_t pipe_read(libp2p_conn_t *c, void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    ssize_t n = read(p->rfd, buf, len);
    if (n > 0)
        return n;
    if (n == 0)
        return LIBP2P_CONN_ERR_EOF;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return LIBP2P_CONN_ERR_AGAIN;
    return LIBP2P_CONN_ERR_INTERNAL;
}

static ssize_t pipe_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    pipe_ctx_t *p = c->ctx;
    ssize_t n = write(p->wfd, buf, len);
    if (n >= 0)
        return n;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return LIBP2P_CONN_ERR_AGAIN;
    return LIBP2P_CONN_ERR_INTERNAL;
}

static libp2p_conn_err_t pipe_deadline(libp2p_conn_t *c, uint64_t ms)
{
    (void)c;
    (void)ms;
    return LIBP2P_CONN_OK;
}

static const multiaddr_t *pipe_addr(libp2p_conn_t *c)
{
    (void)c;
    return NULL;
}

static libp2p_conn_err_t pipe_close(libp2p_conn_t *c)
{
    pipe_ctx_t *p = c->ctx;
    if (p)
    {
        close(p->rfd);
        close(p->wfd);
    }
    return LIBP2P_CONN_OK;
}

static void pipe_free(libp2p_conn_t *c)
{
    pipe_ctx_t *p = c->ctx;
    free(p);
}

static const libp2p_conn_vtbl_t PIPE_VTBL = {
    .read = pipe_read,
    .write = pipe_write,
    .set_deadline = pipe_deadline,
    .local_addr = pipe_addr,
    .remote_addr = pipe_addr,
    .close = pipe_close,
    .free = pipe_free,
};

static void make_pipe_pair(libp2p_conn_t *a, libp2p_conn_t *b)
{
    int ab[2];
    int ba[2];
    assert(pipe(ab) == 0 && pipe(ba) == 0);
    fcntl(ab[0], F_SETFL, O_NONBLOCK);
    fcntl(ab[1], F_SETFL, O_NONBLOCK);
    fcntl(ba[0], F_SETFL, O_NONBLOCK);
    fcntl(ba[1], F_SETFL, O_NONBLOCK);
    pipe_ctx_t *actx = malloc(sizeof(*actx));
    pipe_ctx_t *bctx = malloc(sizeof(*bctx));
    assert(actx && bctx);
    actx->rfd = ba[0];
    actx->wfd = ab[1];
    bctx->rfd = ab[0];
    bctx->wfd = ba[1];
    a->vt = &PIPE_VTBL;
    a->ctx = actx;
    b->vt = &PIPE_VTBL;
    b->ctx = bctx;
}

static void *dial_thread(void *arg)
{
    libp2p_conn_t *c = arg;
    g_dial_rc = libp2p_yamux_negotiate_outbound(c, 5000);
    return NULL;
}

static void *listen_thread(void *arg)
{
    libp2p_conn_t *c = arg;
    g_listen_rc = libp2p_yamux_negotiate_inbound(c, 5000);
    return NULL;
}

static void *loop_thread(void *arg)
{
    g_loop_rc = libp2p_yamux_process_loop((libp2p_yamux_ctx_t *)arg);
    return NULL;
}

static void test_negotiate(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4311", &err);
    assert(addr && err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    int ok = (g_dial_rc == LIBP2P_YAMUX_OK && g_listen_rc == LIBP2P_YAMUX_OK);
    printf("TEST: yamux negotiate %s\n", ok ? "PASS" : "FAIL");

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

struct mux_args
{
    libp2p_muxer_t *m;
    libp2p_conn_t *c;
};
static libp2p_muxer_err_t g_mux_dial_rc;
static libp2p_muxer_err_t g_mux_listen_rc;

static void *dial_mux_thread(void *arg)
{
    struct mux_args *a = arg;
    g_mux_dial_rc = libp2p_muxer_negotiate_outbound(a->m, a->c, 5000);
    return NULL;
}

static void *listen_mux_thread(void *arg)
{
    struct mux_args *a = arg;
    g_mux_listen_rc = libp2p_muxer_negotiate_inbound(a->m, a->c, 5000);
    return NULL;
}

static void test_muxer_wrapper(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4322", &err);
    assert(addr && err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    libp2p_muxer_t *m_dial = libp2p_yamux_new();
    libp2p_muxer_t *m_listen = libp2p_yamux_new();
    assert(m_dial && m_listen);

    struct mux_args dargs = {m_dial, c};
    struct mux_args sargs = {m_listen, s};
    pthread_t td, ts;
    pthread_create(&td, NULL, dial_mux_thread, &dargs);
    pthread_create(&ts, NULL, listen_mux_thread, &sargs);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    int ok = (g_mux_dial_rc == LIBP2P_MUXER_OK && g_mux_listen_rc == LIBP2P_MUXER_OK);
    printf("TEST: yamux muxer wrapper negotiation %s\n", ok ? "PASS" : "FAIL");

    libp2p_muxer_free(m_dial);
    libp2p_muxer_free(m_listen);
    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_frame_roundtrip(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4312", &err);
    assert(addr && err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);
    assert(g_dial_rc == LIBP2P_YAMUX_OK && g_listen_rc == LIBP2P_YAMUX_OK);

    const char *msg = "hi";
    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 3,
        .length = 2,
        .data = (uint8_t *)msg,
        .data_len = 2,
    };
    assert(libp2p_yamux_send_frame(c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t rec = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(s, &rec);

    int ok = (rc == LIBP2P_YAMUX_OK && rec.stream_id == 3 && rec.data_len == 2 && memcmp(rec.data, msg, 2) == 0);
    printf("TEST: yamux frame roundtrip %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&rec);
    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

typedef struct
{
    libp2p_conn_t *conn;
    libp2p_yamux_frame_t fr;
    libp2p_yamux_err_t rc;
} read_arg_t;

static void *read_frame_thread(void *arg)
{
    read_arg_t *ra = arg;
    ra->rc = libp2p_yamux_read_frame(ra->conn, &ra->fr);
    return NULL;
}

static void test_large_frame(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    size_t len = 2 * 1024 * 1024; /* 2 MiB */
    uint8_t *buf = malloc(len);
    assert(buf);
    memset(buf, 'x', len);

    read_arg_t ra = {.conn = &s, .fr = {0}, .rc = 0};
    pthread_t th;
    pthread_create(&th, NULL, read_frame_thread, &ra);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 3,
        .length = (uint32_t)len,
        .data = buf,
        .data_len = len,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    pthread_join(th, NULL);

    int ok = (ra.rc == LIBP2P_YAMUX_OK && ra.fr.stream_id == 3 && ra.fr.data_len == len && memcmp(ra.fr.data, buf, len) == 0);
    printf("TEST: yamux large frame %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&ra.fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
    free(buf);
}

static void test_invalid_version(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_frame_t fr = {
        .version = 1,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 3,
        .length = 0,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t rec = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &rec);

    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    printf("TEST: yamux invalid version %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&rec);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_stream_id_zero(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(srv);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = 0,
        .stream_id = 0,
        .length = 0,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_err_t rc = libp2p_yamux_process_one(srv);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    printf("TEST: yamux stream id zero %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_stream_id_parity(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(srv);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_DATA,
        .flags = LIBP2P_YAMUX_SYN,
        .stream_id = 2,
        .length = 0,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_err_t rc = libp2p_yamux_process_one(srv);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    printf("TEST: yamux stream id parity %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_window_update(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    assert(libp2p_yamux_window_update(&c, 5, 123, 0) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && fr.stream_id == 5 && fr.length == 123);
    printf("TEST: yamux window update %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_ping_pong(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    assert(libp2p_yamux_ping(&c, 42, LIBP2P_YAMUX_SYN) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_PING && fr.length == 42 && (fr.flags & LIBP2P_YAMUX_SYN));

    printf("TEST: yamux ping %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);

    assert(libp2p_yamux_ping(&s, 42, LIBP2P_YAMUX_ACK) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t ack = {0};
    rc = libp2p_yamux_read_frame(&c, &ack);
    ok = (rc == LIBP2P_YAMUX_OK && ack.type == LIBP2P_YAMUX_PING && ack.length == 42 && (ack.flags & LIBP2P_YAMUX_ACK));
    printf("TEST: yamux ping ack %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&ack);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void ping_cb(libp2p_yamux_ctx_t *ctx, uint32_t value, uint64_t rtt_ms, void *arg)
{
    (void)ctx;
    (void)value;
    *(uint64_t *)arg = rtt_ms;
}

static void test_ping_callback(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    uint64_t rtt = 0;
    libp2p_yamux_set_ping_cb(ctx, ping_cb, &rtt);

    assert(libp2p_yamux_ctx_ping(ctx, 7) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);
    assert(rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_PING);
    assert(libp2p_yamux_ping(&s, fr.length, LIBP2P_YAMUX_ACK) == LIBP2P_YAMUX_OK);
    libp2p_yamux_frame_free(&fr);

    rc = libp2p_yamux_process_one(ctx);
    int ok = (rc == LIBP2P_YAMUX_OK && rtt >= 0);
    printf("TEST: yamux ping callback %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_ping_bad_flags(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_PING,
        .flags = LIBP2P_YAMUX_SYN | LIBP2P_YAMUX_ACK,
        .stream_id = 0,
        .length = 1,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    printf("TEST: yamux ping bad flags %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    assert(libp2p_yamux_go_away(&c, LIBP2P_YAMUX_GOAWAY_OK) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_GO_AWAY && fr.length == LIBP2P_YAMUX_GOAWAY_OK);
    printf("TEST: yamux go away %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_stop_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_stop(ctx);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_GO_AWAY && fr.length == LIBP2P_YAMUX_GOAWAY_OK);
    printf("TEST: yamux stop go away %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_open_after_stop(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_stop(ctx);

    uint32_t id = 0;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_open(ctx, &id);

    int ok = (rc == LIBP2P_YAMUX_ERR_EOF);
    printf("TEST: yamux open after stop %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_ctx_free_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_ctx_free(ctx);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_GO_AWAY && fr.length == LIBP2P_YAMUX_GOAWAY_OK);
    printf("TEST: yamux ctx free go away %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_go_away_flags(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    libp2p_yamux_frame_t fr = {
        .version = 0,
        .type = LIBP2P_YAMUX_GO_AWAY,
        .flags = LIBP2P_YAMUX_SYN,
        .stream_id = 0,
        .length = LIBP2P_YAMUX_GOAWAY_OK,
        .data = NULL,
        .data_len = 0,
    };
    assert(libp2p_yamux_send_frame(&c, &fr) == LIBP2P_YAMUX_OK);

    libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
    int ok = (rc == LIBP2P_YAMUX_ERR_PROTO_MAL);
    printf("TEST: yamux go away flags %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_send_window(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);
    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(ctx, &id) == LIBP2P_YAMUX_OK);

    pthread_mutex_lock(&ctx->mtx);
    ctx->streams[0]->send_window = 1;
    pthread_mutex_unlock(&ctx->mtx);

    uint8_t buf[4] = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_stream_send(ctx, id, buf, sizeof(buf), 0);
    int ok = (rc == LIBP2P_YAMUX_ERR_AGAIN);
    printf("TEST: yamux send window %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_recv_window_update(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(cli, &id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    libp2p_yamux_stream_t *st = NULL;
    assert(libp2p_yamux_accept_stream(srv, &st) == LIBP2P_YAMUX_OK);

    const char *msg = "test";
    assert(libp2p_yamux_stream_send(cli, id, (const uint8_t *)msg, 4, 0) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    pthread_mutex_lock(&srv->mtx);
    size_t rw = srv->streams[0]->recv_window;
    pthread_mutex_unlock(&srv->mtx);
    int ok = (rw == srv->max_window - 4);

    uint8_t rbuf[4];
    size_t n = 0;
    assert(libp2p_yamux_stream_recv(srv, id, rbuf, sizeof(rbuf), &n) == LIBP2P_YAMUX_OK);
    assert(n == 4 && memcmp(rbuf, msg, 4) == 0);

    pthread_mutex_lock(&srv->mtx);
    rw = srv->streams[0]->recv_window;
    pthread_mutex_unlock(&srv->mtx);
    ok = ok && (rw == srv->max_window);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    if (fr.type == LIBP2P_YAMUX_DATA && (fr.flags & LIBP2P_YAMUX_ACK))
    {
        libp2p_yamux_frame_free(&fr);
        assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    }
    ok = ok && (fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && fr.stream_id == id && fr.length > 0);
    printf("TEST: yamux recv window update %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_delayed_ack(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(cli, &id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    libp2p_yamux_stream_t *st = NULL;
    assert(libp2p_yamux_accept_stream(srv, &st) == LIBP2P_YAMUX_OK);

    pthread_mutex_lock(&srv->mtx);
    int acked = srv->streams[0]->acked;
    pthread_mutex_unlock(&srv->mtx);
    int ok = (acked == 0);

    const char *msg = "hi";
    assert(libp2p_yamux_stream_send(srv, id, (const uint8_t *)msg, 2, 0) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    ok = ok && (fr.type == LIBP2P_YAMUX_DATA && (fr.flags & LIBP2P_YAMUX_ACK));
    libp2p_yamux_frame_free(&fr);

    pthread_mutex_lock(&srv->mtx);
    acked = srv->streams[0]->acked;
    pthread_mutex_unlock(&srv->mtx);
    ok = ok && (acked == 1);

    printf("TEST: yamux delayed ack %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_initial_window_syn(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    uint32_t big = YAMUX_INITIAL_WINDOW * 2;
    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, big);
    assert(ctx);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(ctx, &id) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&s, &fr) == LIBP2P_YAMUX_OK);
    int ok =
        (fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && (fr.flags & LIBP2P_YAMUX_SYN) && fr.stream_id == id && fr.length == big - YAMUX_INITIAL_WINDOW);
    printf("TEST: yamux large window syn %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_initial_window_ack(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    uint32_t big = YAMUX_INITIAL_WINDOW * 2;
    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, big);
    assert(cli && srv);

    uint32_t id = 0;
    assert(libp2p_yamux_stream_open(cli, &id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    assert(libp2p_yamux_read_frame(&c, &fr) == LIBP2P_YAMUX_OK);
    int ok =
        (fr.type == LIBP2P_YAMUX_WINDOW_UPDATE && (fr.flags & LIBP2P_YAMUX_ACK) && fr.stream_id == id && fr.length == big - YAMUX_INITIAL_WINDOW);
    printf("TEST: yamux large window ack %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_keepalive(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    assert(libp2p_yamux_enable_keepalive(ctx, 50) == LIBP2P_YAMUX_OK);

    usleep(120000); /* allow ping to be sent */

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);
    int ok = (rc == LIBP2P_YAMUX_OK && fr.type == LIBP2P_YAMUX_PING && (fr.flags & LIBP2P_YAMUX_SYN));
    printf("TEST: yamux keepalive ping %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_stop(ctx);

    // Give the background keepalive thread time to properly exit
    usleep(100000); // 100ms

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_recv_go_away(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    assert(libp2p_yamux_go_away(&s, LIBP2P_YAMUX_GOAWAY_OK) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(ctx) == LIBP2P_YAMUX_OK);

    libp2p_yamux_frame_t fr = {0};
    libp2p_yamux_err_t rc = libp2p_yamux_read_frame(&s, &fr);

    int ok = (rc == LIBP2P_YAMUX_ERR_EOF && ctx->goaway_received && ctx->goaway_code == LIBP2P_YAMUX_GOAWAY_OK);
    printf("TEST: yamux recv go away %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&fr);
    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test yamux muxer creation and basic functionality
 * This verifies the yamux implementation basics work as expected
 */
static void test_yamux_muxer_creation(void)
{
    libp2p_muxer_t *muxer = libp2p_yamux_new();
    assert(muxer != NULL);
    assert(muxer->ctx == NULL); // Context should be NULL until negotiation

    printf("TEST: yamux muxer creation PASS\n");

    libp2p_muxer_free(muxer);
}

/**
 * Test yamux frame operations work correctly without hanging
 * This verifies basic frame send/receive functionality that interop tests rely on
 */
static void test_yamux_frame_operations(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    // Test basic frame send/receive
    libp2p_yamux_frame_t send_frame = {
        .version = 0,
        .type = LIBP2P_YAMUX_PING,
        .flags = LIBP2P_YAMUX_SYN,
        .stream_id = 0,
        .length = 42,
        .data = NULL,
        .data_len = 0,
    };

    libp2p_yamux_err_t send_rc = libp2p_yamux_send_frame(&c, &send_frame);
    if (send_rc != LIBP2P_YAMUX_OK)
    {
        printf("TEST: yamux frame operations FAIL (send failed: %d)\n", send_rc);
        goto cleanup;
    }

    libp2p_yamux_frame_t recv_frame = {0};
    libp2p_yamux_err_t recv_rc = libp2p_yamux_read_frame(&s, &recv_frame);
    if (recv_rc != LIBP2P_YAMUX_OK)
    {
        printf("TEST: yamux frame operations FAIL (recv failed: %d)\n", recv_rc);
        goto cleanup;
    }

    int ok = (recv_frame.type == LIBP2P_YAMUX_PING && recv_frame.flags == LIBP2P_YAMUX_SYN && recv_frame.length == 42);

    printf("TEST: yamux frame operations %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_frame_free(&recv_frame);

cleanup:
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test multiple concurrent streams handling
 * This test ensures multi-stream protocol handling works correctly
 */
static void test_multiple_concurrent_streams(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    const int num_streams = 5;
    uint32_t stream_ids[num_streams];

    // Open multiple streams
    for (int i = 0; i < num_streams; i++)
    {
        assert(libp2p_yamux_stream_open(cli, &stream_ids[i]) == LIBP2P_YAMUX_OK);
    }

    // Process all incoming streams on server
    for (int i = 0; i < num_streams; i++)
    {
        assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    }

    // Send data on all streams
    for (int i = 0; i < num_streams; i++)
    {
        char data[32];
        snprintf(data, sizeof(data), "Stream %d data", i);
        assert(libp2p_yamux_stream_send(cli, stream_ids[i], (const uint8_t *)data, strlen(data), 0) == LIBP2P_YAMUX_OK);
    }

    // Process all data frames on server
    for (int i = 0; i < num_streams; i++)
    {
        assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);
    }

    // Verify all streams received correct data
    int all_correct = 1;
    for (int i = 0; i < num_streams; i++)
    {
        uint8_t buf[64];
        size_t len = 0;
        libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(srv, stream_ids[i], buf, sizeof(buf), &len);

        char expected[32];
        snprintf(expected, sizeof(expected), "Stream %d data", i);

        if (rc != LIBP2P_YAMUX_OK || len != strlen(expected) || memcmp(buf, expected, strlen(expected)) != 0)
        {
            all_correct = 0;
            break;
        }
    }

    printf("TEST: yamux multiple concurrent streams %s\n", all_correct ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test yamux muxer context storage after negotiation
 * This test prevents regression where context wasn't stored in muxer->ctx
 */
static void test_muxer_context_storage(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_muxer_t *m_dial = libp2p_yamux_new();
    libp2p_muxer_t *m_listen = libp2p_yamux_new();
    assert(m_dial && m_listen);

    // Initially, context should be NULL
    assert(m_dial->ctx == NULL);
    assert(m_listen->ctx == NULL);

    struct mux_args dargs = {m_dial, &c};
    struct mux_args sargs = {m_listen, &s};
    pthread_t td, ts;
    pthread_create(&td, NULL, dial_mux_thread, &dargs);
    pthread_create(&ts, NULL, listen_mux_thread, &sargs);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    // After successful negotiation, context should be stored in muxer->ctx
    int ok = (g_mux_dial_rc == LIBP2P_MUXER_OK && g_mux_listen_rc == LIBP2P_MUXER_OK && m_dial->ctx != NULL && m_listen->ctx != NULL);
    printf("TEST: yamux muxer context storage after negotiation %s\n", ok ? "PASS" : "FAIL");

    libp2p_muxer_free(m_dial);
    libp2p_muxer_free(m_listen);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test partial frame reading to ensure non-blocking behavior
 * This test verifies that partial frame reads are handled correctly
 */
static void test_partial_frame_reading(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *ctx = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(ctx);

    // Send partial frame header
    uint8_t partial_header[6] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00}; // Version 0, Type DATA, partial flags
    assert(libp2p_conn_write(&c, partial_header, sizeof(partial_header)) == sizeof(partial_header));

    // Try to process - should return AGAIN since frame is incomplete
    libp2p_yamux_err_t rc = libp2p_yamux_process_one(ctx);
    int ok = (rc == LIBP2P_YAMUX_ERR_AGAIN);

    // Complete the frame
    uint8_t rest_header[6] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00}; // Stream ID 1, Length 0
    assert(libp2p_conn_write(&c, rest_header, sizeof(rest_header)) == sizeof(rest_header));

    // Now processing should work
    rc = libp2p_yamux_process_one(ctx);
    ok = ok && (rc == LIBP2P_YAMUX_OK);

    printf("TEST: yamux partial frame reading %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(ctx);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test stream flow control with window updates
 * This test ensures flow control works correctly with window updates
 */
static void test_stream_flow_control(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    // Open a stream
    uint32_t stream_id = 0;
    assert(libp2p_yamux_stream_open(cli, &stream_id) == LIBP2P_YAMUX_OK);
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    // Reduce send window to test flow control
    pthread_mutex_lock(&cli->mtx);
    if (cli->num_streams > 0)
    {
        cli->streams[0]->send_window = 10; // Very small window
    }
    pthread_mutex_unlock(&cli->mtx);

    // Try to send more data than window allows
    uint8_t large_data[100];
    memset(large_data, 'x', sizeof(large_data));
    libp2p_yamux_err_t rc = libp2p_yamux_stream_send(cli, stream_id, large_data, sizeof(large_data), 0);

    // Should fail with AGAIN due to flow control
    int ok = (rc == LIBP2P_YAMUX_ERR_AGAIN);
    printf("TEST: yamux stream flow control %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

/**
 * Test basic stream data exchange without process loop
 * This test verifies that data can be sent and received between streams
 */
static void test_basic_stream_data_exchange(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_yamux_ctx_t *cli = libp2p_yamux_ctx_new(&c, 1, YAMUX_INITIAL_WINDOW);
    libp2p_yamux_ctx_t *srv = libp2p_yamux_ctx_new(&s, 0, YAMUX_INITIAL_WINDOW);
    assert(cli && srv);

    // Open a stream
    uint32_t stream_id = 0;
    assert(libp2p_yamux_stream_open(cli, &stream_id) == LIBP2P_YAMUX_OK);

    // Process the stream open on server
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    // Send data from client to server
    const char *test_data = "Hello yamux!";
    size_t test_len = strlen(test_data);
    assert(libp2p_yamux_stream_send(cli, stream_id, (const uint8_t *)test_data, test_len, 0) == LIBP2P_YAMUX_OK);

    // Process the data frame on server
    assert(libp2p_yamux_process_one(srv) == LIBP2P_YAMUX_OK);

    // Receive data on server
    uint8_t recv_buf[64];
    size_t recv_len = 0;
    libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(srv, stream_id, recv_buf, sizeof(recv_buf), &recv_len);

    int ok = (rc == LIBP2P_YAMUX_OK && recv_len == test_len && memcmp(recv_buf, test_data, test_len) == 0);
    printf("TEST: yamux basic stream data exchange %s\n", ok ? "PASS" : "FAIL");

    libp2p_yamux_ctx_free(cli);
    libp2p_yamux_ctx_free(srv);
    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

int main(void)
{
    test_negotiate();
    test_muxer_wrapper();
    test_frame_roundtrip();
    test_invalid_version();
    test_stream_id_zero();
    test_stream_id_parity();
    test_window_update();
    test_ping_pong();
    test_ping_callback();
    test_ping_bad_flags();
    test_go_away();
    test_stop_go_away();
    test_open_after_stop();
    test_ctx_free_go_away();
    test_go_away_flags();
    test_send_window();
    test_recv_window_update();
    test_initial_window_syn();
    test_initial_window_ack();
    test_delayed_ack();
    test_keepalive();
    test_large_frame();
    test_recv_go_away();

    // New regression tests for yamux fixes from debug report
    test_yamux_muxer_creation();
    test_yamux_frame_operations();
    test_multiple_concurrent_streams();
    test_muxer_context_storage();
    test_basic_stream_data_exchange();

    return 0;
}
