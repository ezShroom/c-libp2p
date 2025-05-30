#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/tcp/protocol_tcp.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#ifndef _O_BINARY
#define _O_BINARY 0x8000
#endif
static inline int pipe(int fds[2])
{
    /* size 4096, binary mode */
    return _pipe(fds, 4096, _O_BINARY);
}
#endif /* _WIN32 */

/* dummy connection that never becomes writable to simulate a slow reader */
static ssize_t slow_read(libp2p_conn_t *c, void *buf, size_t len)
{
    (void)c;
    (void)buf;
    (void)len;
    return LIBP2P_CONN_ERR_AGAIN;
}
static ssize_t slow_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    (void)c;
    (void)buf;
    (void)len;
    return LIBP2P_CONN_ERR_AGAIN;
}
static libp2p_conn_err_t slow_deadline(libp2p_conn_t *c, uint64_t ms)
{
    (void)c;
    (void)ms;
    return LIBP2P_CONN_OK;
}
static const multiaddr_t *slow_addr(libp2p_conn_t *c)
{
    (void)c;
    return NULL;
}
static libp2p_conn_err_t slow_close(libp2p_conn_t *c)
{
    (void)c;
    return LIBP2P_CONN_OK;
}
static void slow_free(libp2p_conn_t *c) { (void)c; }
static const libp2p_conn_vtbl_t SLOW_VTBL = {
    .read = slow_read,
    .write = slow_write,
    .set_deadline = slow_deadline,
    .local_addr = slow_addr,
    .remote_addr = slow_addr,
    .close = slow_close,
    .free = slow_free,
};

/* dummy connection that always succeeds */
static ssize_t ok_read(libp2p_conn_t *c, void *buf, size_t len)
{
    (void)c;
    if (buf && len)
        memset(buf, 0, len);
    return (ssize_t)len;
}
static ssize_t ok_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    (void)c;
    (void)buf;
    return (ssize_t)len;
}
static libp2p_conn_err_t ok_deadline(libp2p_conn_t *c, uint64_t ms)
{
    (void)c;
    (void)ms;
    return LIBP2P_CONN_OK;
}
static const multiaddr_t *ok_addr(libp2p_conn_t *c)
{
    (void)c;
    return NULL;
}
static libp2p_conn_err_t ok_close(libp2p_conn_t *c)
{
    (void)c;
    return LIBP2P_CONN_OK;
}
static void ok_free(libp2p_conn_t *c) { (void)c; }
static const libp2p_conn_vtbl_t OK_VTBL = {
    .read = ok_read,
    .write = ok_write,
    .set_deadline = ok_deadline,
    .local_addr = ok_addr,
    .remote_addr = ok_addr,
    .close = ok_close,
    .free = ok_free,
};

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

static void print_standard(const char *name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", name);
    else
        printf("TEST: %-50s | FAIL: %s\n", name, details);
}

static libp2p_mplex_err_t g_dial_rc;
static libp2p_mplex_err_t g_listen_rc;

static void *dial_thread(void *arg)
{
    libp2p_conn_t *c = (libp2p_conn_t *)arg;
    g_dial_rc = libp2p_mplex_negotiate_outbound(c, 5000);
    return NULL;
}

static void *listen_thread(void *arg)
{
    libp2p_conn_t *c = (libp2p_conn_t *)arg;
    g_listen_rc = libp2p_mplex_negotiate_inbound(c, 5000);
    return NULL;
}

static void test_negotiate_success(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4021", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    int ok = (g_dial_rc == LIBP2P_MPLEX_OK && g_listen_rc == LIBP2P_MPLEX_OK);
    print_standard("mplex negotiate success", ok ? "" : "", ok);

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
    struct mux_args *a = (struct mux_args *)arg;
    g_mux_dial_rc = libp2p_muxer_negotiate_outbound(a->m, a->c, 5000);
    return NULL;
}

static void *listen_mux_thread(void *arg)
{
    struct mux_args *a = (struct mux_args *)arg;
    g_mux_listen_rc = libp2p_muxer_negotiate_inbound(a->m, a->c, 5000);
    return NULL;
}

static void test_muxer_wrapper(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4022", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    libp2p_muxer_t *m_dial = libp2p_mplex_new();
    libp2p_muxer_t *m_listen = libp2p_mplex_new();
    assert(m_dial && m_listen);

    struct mux_args dargs = {m_dial, c};
    struct mux_args sargs = {m_listen, s};
    pthread_t td, ts;
    pthread_create(&td, NULL, dial_mux_thread, &dargs);
    pthread_create(&ts, NULL, listen_mux_thread, &sargs);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);

    int ok = (g_mux_dial_rc == LIBP2P_MUXER_OK && g_mux_listen_rc == LIBP2P_MUXER_OK);
    print_standard("muxer wrapper negotiation", ok ? "" : "", ok);

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

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4023", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);
    assert(g_dial_rc == LIBP2P_MPLEX_OK && g_listen_rc == LIBP2P_MPLEX_OK);

    libp2p_mplex_frame_t fr = {
        .id = 7,
        .flag = LIBP2P_MPLEX_MSG_INITIATOR,
        .data = (uint8_t *)"hello",
        .data_len = 5,
    };
    assert(libp2p_mplex_send_frame(c, &fr) == LIBP2P_MPLEX_OK);

    libp2p_mplex_frame_t rec = {0};
    libp2p_mplex_err_t rcrc = libp2p_mplex_read_frame(s, &rec);
    if (rcrc != LIBP2P_MPLEX_OK)
    {
        char details[64];
        snprintf(details, sizeof(details), "rc=%d", (int)rcrc);
        print_standard("mplex frame roundtrip", details, 0);
        libp2p_conn_close(c);
        libp2p_conn_close(s);
        libp2p_conn_free(c);
        libp2p_conn_free(s);
        libp2p_listener_close(lst);
        libp2p_transport_close(tcp);
        multiaddr_free(addr);
        libp2p_transport_free(tcp);
        return;
    }
    int ok = rec.id == fr.id && rec.flag == fr.flag && rec.data_len == fr.data_len && memcmp(rec.data, fr.data, fr.data_len) == 0;
    print_standard("mplex frame roundtrip", ok ? "" : "", ok);
    libp2p_mplex_frame_free(&rec);

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_helper_functions(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4024", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);
    assert(g_dial_rc == LIBP2P_MPLEX_OK && g_listen_rc == LIBP2P_MPLEX_OK);

    assert(libp2p_mplex_open_stream(c, 3, (const uint8_t *)"s", 1) == LIBP2P_MPLEX_OK);
    libp2p_mplex_frame_t fr = {0};
    libp2p_mplex_err_t rc = libp2p_mplex_read_frame(s, &fr);
    if (rc != LIBP2P_MPLEX_OK)
    {
        char details[32];
        snprintf(details, sizeof(details), "rc=%d", (int)rc);
        print_standard("mplex open_stream", details, 0);
        goto cleanup;
    }
    int ok = fr.id == 3 && fr.flag == LIBP2P_MPLEX_NEW_STREAM && fr.data_len == 1 && memcmp(fr.data, "s", 1) == 0;
    print_standard("mplex open_stream", ok ? "" : "", ok);
    libp2p_mplex_frame_free(&fr);

    assert(libp2p_mplex_send_msg(c, 3, 1, (const uint8_t *)"abc", 3) == LIBP2P_MPLEX_OK);
    assert(libp2p_mplex_read_frame(s, &fr) == LIBP2P_MPLEX_OK);
    ok = fr.id == 3 && fr.flag == LIBP2P_MPLEX_MSG_INITIATOR && fr.data_len == 3 && memcmp(fr.data, "abc", 3) == 0;
    print_standard("mplex send_msg", ok ? "" : "", ok);
    libp2p_mplex_frame_free(&fr);

    assert(libp2p_mplex_close_stream(c, 3, 1) == LIBP2P_MPLEX_OK);
    assert(libp2p_mplex_read_frame(s, &fr) == LIBP2P_MPLEX_OK);
    ok = fr.id == 3 && fr.flag == LIBP2P_MPLEX_CLOSE_INITIATOR && fr.data_len == 0;
    print_standard("mplex close_stream", ok ? "" : "", ok);
    libp2p_mplex_frame_free(&fr);

cleanup:
    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_header_varint_too_long(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4025", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);
    assert(g_dial_rc == LIBP2P_MPLEX_OK && g_listen_rc == LIBP2P_MPLEX_OK);

    uint8_t hdr[10];
    memset(hdr, 0x80, sizeof(hdr));
    assert(libp2p_conn_write(c, hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr));
    uint8_t len = 0;
    assert(libp2p_conn_write(c, &len, 1) == 1);

    libp2p_mplex_frame_t fr = {0};
    libp2p_mplex_err_t rc = libp2p_mplex_read_frame(s, &fr);
    int ok = (rc == LIBP2P_MPLEX_ERR_PROTO_MAL);
    print_standard("mplex header varint too long", ok ? "" : "", ok);
    if (rc == LIBP2P_MPLEX_OK)
        libp2p_mplex_frame_free(&fr);

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_length_varint_too_long(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4026", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    pthread_t td, ts;
    pthread_create(&td, NULL, dial_thread, c);
    pthread_create(&ts, NULL, listen_thread, s);
    pthread_join(td, NULL);
    pthread_join(ts, NULL);
    assert(g_dial_rc == LIBP2P_MPLEX_OK && g_listen_rc == LIBP2P_MPLEX_OK);

    uint8_t hdr_buf[10];
    size_t hdr_len;
    uint64_t hdr_val = ((uint64_t)1 << 3) | LIBP2P_MPLEX_MSG_INITIATOR;
    assert(unsigned_varint_encode(hdr_val, hdr_buf, sizeof(hdr_buf), &hdr_len) == 0);
    assert(libp2p_conn_write(c, hdr_buf, hdr_len) == (ssize_t)hdr_len);
    uint8_t bad_len[10];
    memset(bad_len, 0x80, sizeof(bad_len));
    assert(libp2p_conn_write(c, bad_len, sizeof(bad_len)) == (ssize_t)sizeof(bad_len));

    libp2p_mplex_frame_t fr = {0};
    libp2p_mplex_err_t rc = libp2p_mplex_read_frame(s, &fr);
    int ok = (rc == LIBP2P_MPLEX_ERR_PROTO_MAL);
    print_standard("mplex length varint too long", ok ? "" : "", ok);
    if (rc == LIBP2P_MPLEX_OK)
        libp2p_mplex_frame_free(&fr);

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_ctx_dispatch(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 5;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);
    assert(ctx->streams.len == 1 && ctx->streams.items[0]->id == 5 && ctx->streams.items[0]->initiator == 0);

    fr.flag = LIBP2P_MPLEX_CLOSE_INITIATOR;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);
    assert(ctx->streams.items[0]->remote_closed == 1);

    fr.flag = LIBP2P_MPLEX_RESET_INITIATOR;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);
    assert(ctx->streams.len == 1 && ctx->streams.items[0]->reset == 1);

    uint8_t tmp[4];
    size_t n = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(ctx, 5, 0, tmp, sizeof(tmp), &n);
    assert(rc == LIBP2P_MPLEX_ERR_RESET && n == 0);
    assert(ctx->streams.len == 0);

    libp2p_mplex_ctx_free(ctx);
}

static void test_stream_recv_buffer(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 1;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    const char *msg = "hello";
    fr.flag = LIBP2P_MPLEX_MSG_RECEIVER;
    fr.data = (uint8_t *)msg;
    fr.data_len = 5;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    uint8_t out[8];
    size_t n = 0;
    assert(libp2p_mplex_stream_recv(ctx, 1, 0, out, sizeof(out), &n) == LIBP2P_MPLEX_OK);
    int ok = n == 5 && memcmp(out, msg, 5) == 0;
    print_standard("mplex stream recv", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static libp2p_mplex_err_t g_loop_rc;

static void *loop_thread(void *arg)
{
    g_loop_rc = libp2p_mplex_process_loop((libp2p_mplex_ctx_t *)arg);
    return NULL;
}

static void test_process_loop(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_mplex_ctx_t *ctx_c = libp2p_mplex_ctx_new(&c);
    libp2p_mplex_ctx_t *ctx_s = libp2p_mplex_ctx_new(&s);
    assert(ctx_c && ctx_s);

    pthread_t tl;
    pthread_create(&tl, NULL, loop_thread, ctx_s);

    uint64_t sid = 0;
    assert(libp2p_mplex_stream_open(ctx_c, (const uint8_t *)"s", 1, &sid) == LIBP2P_MPLEX_OK);
    assert(libp2p_mplex_stream_send(ctx_c, sid, 1, (const uint8_t *)"hi", 2) == LIBP2P_MPLEX_OK);

    usleep(10000);

    uint8_t out[8];
    size_t n = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(ctx_s, sid, 0, out, sizeof(out), &n);
    int ok = (rc == LIBP2P_MPLEX_OK && n == 2 && memcmp(out, "hi", 2) == 0);
    print_standard("mplex processing loop", ok ? "" : "", ok);

    libp2p_mplex_stop(ctx_s);
    libp2p_conn_close(&c);
    pthread_join(tl, NULL);
    libp2p_conn_close(&s);

    libp2p_mplex_ctx_free(ctx_c);
    libp2p_mplex_ctx_free(ctx_s);

    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_process_one(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_mplex_ctx_t *ctx_c = libp2p_mplex_ctx_new(&c);
    libp2p_mplex_ctx_t *ctx_s = libp2p_mplex_ctx_new(&s);
    assert(ctx_c && ctx_s);

    uint64_t sid = 0;
    assert(libp2p_mplex_stream_open(ctx_c, (const uint8_t *)"s", 1, &sid) == LIBP2P_MPLEX_OK);
    assert(libp2p_mplex_stream_send(ctx_c, sid, 1, (const uint8_t *)"hi", 2) == LIBP2P_MPLEX_OK);

    assert(libp2p_mplex_process_one(ctx_s) == LIBP2P_MPLEX_OK);
    assert(libp2p_mplex_process_one(ctx_s) == LIBP2P_MPLEX_OK);

    uint8_t out[4];
    size_t n = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(ctx_s, sid, 0, out, sizeof(out), &n);
    int ok = (rc == LIBP2P_MPLEX_OK && n == 2 && memcmp(out, "hi", 2) == 0);
    print_standard("mplex process one", ok ? "" : "", ok);

    libp2p_conn_close(&c);
    libp2p_conn_close(&s);
    libp2p_mplex_ctx_free(ctx_c);
    libp2p_mplex_ctx_free(ctx_s);
    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_inbound_stream_queue(void)
{
    libp2p_conn_t c = {0}, s = {0};
    make_pipe_pair(&c, &s);

    libp2p_mplex_ctx_t *ctx_c = libp2p_mplex_ctx_new(&c);
    libp2p_mplex_ctx_t *ctx_s = libp2p_mplex_ctx_new(&s);
    assert(ctx_c && ctx_s);

    pthread_t tl;
    pthread_create(&tl, NULL, loop_thread, ctx_s);

    uint64_t sid = 0;
    assert(libp2p_mplex_stream_open(ctx_c, (const uint8_t *)"x", 1, &sid) == LIBP2P_MPLEX_OK);

    usleep(10000);

    libp2p_mplex_stream_t *st = NULL;
    libp2p_mplex_err_t rc = libp2p_mplex_accept_stream(ctx_s, &st);
    int ok = (rc == LIBP2P_MPLEX_OK && st && st->id == sid && st->initiator == 0 && st->name_len == 1 && memcmp(st->name, "x", 1) == 0);
    print_standard("mplex inbound new stream", ok ? "" : "", ok);

    libp2p_mplex_stop(ctx_s);
    libp2p_conn_close(&c);
    pthread_join(tl, NULL);
    libp2p_conn_close(&s);

    libp2p_mplex_ctx_free(ctx_c);
    libp2p_mplex_ctx_free(ctx_s);

    libp2p_conn_free(&c);
    libp2p_conn_free(&s);
}

static void test_slow_reader_reset(void)
{
    libp2p_conn_t conn = {.vt = &SLOW_VTBL, .ctx = NULL};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&conn);
    assert(ctx);

    /* manually add stream */
    libp2p_mplex_stream_t *st = calloc(1, sizeof(*st));
    st->id = 1;
    st->initiator = 1;
    st->name = NULL;
    st->name_len = 0;
    ctx->streams.items = malloc(sizeof(st));
    ctx->streams.cap = 1;
    ctx->streams.items[0] = st;
    ctx->streams.len = 1;

    libp2p_mplex_err_t rc = libp2p_mplex_stream_send(ctx, 1, 1, (const uint8_t *)"hi", 2);
    int ok = (rc == LIBP2P_MPLEX_ERR_TIMEOUT && ctx->streams.len == 0);
    print_standard("mplex slow reader reset", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_recv_buffer_limit_reset(void)
{
    libp2p_conn_t dummy = {.vt = &OK_VTBL, .ctx = NULL};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 6;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    size_t msg_len = 1024 * 1024; /* 1 MiB */
    uint8_t *msg = malloc(msg_len);
    assert(msg);
    memset(msg, 'x', msg_len);

    fr.flag = LIBP2P_MPLEX_MSG_INITIATOR;
    fr.data = msg;
    fr.data_len = msg_len;

    for (int i = 0; i < 5; i++)
        assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    free(msg);

    int ok = (ctx->streams.len == 0);
    print_standard("mplex recv buffer limit reset", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_remote_close_eof(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 7;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    fr.flag = LIBP2P_MPLEX_CLOSE_INITIATOR;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    uint8_t out[4];
    size_t n = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(ctx, 7, 0, out, sizeof(out), &n);
    int ok = (rc == LIBP2P_MPLEX_ERR_EOF && n == 0);
    print_standard("mplex remote close eof", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_data_after_remote_close(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 11;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    fr.flag = LIBP2P_MPLEX_CLOSE_INITIATOR;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    fr.flag = LIBP2P_MPLEX_MSG_INITIATOR;
    fr.data = (uint8_t *)"x";
    fr.data_len = 1;
    libp2p_mplex_err_t rc = libp2p_mplex_dispatch_frame(ctx, &fr);
    int ok = (rc == LIBP2P_MPLEX_ERR_PROTO_MAL && atomic_load_explicit(&ctx->stop, memory_order_relaxed));
    print_standard("mplex data after remote close", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_close_payload(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 8;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    uint8_t extra = 'x';
    fr.flag = LIBP2P_MPLEX_CLOSE_INITIATOR;
    fr.data = &extra;
    fr.data_len = 1;
    libp2p_mplex_err_t rc = libp2p_mplex_dispatch_frame(ctx, &fr);
    int ok = (rc == LIBP2P_MPLEX_ERR_PROTO_MAL && atomic_load_explicit(&ctx->stop, memory_order_relaxed));
    print_standard("mplex close payload", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_reset_payload(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 9;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    uint8_t extra = 'x';
    fr.flag = LIBP2P_MPLEX_RESET_INITIATOR;
    fr.data = &extra;
    fr.data_len = 1;
    libp2p_mplex_err_t rc = libp2p_mplex_dispatch_frame(ctx, &fr);
    int ok = (rc == LIBP2P_MPLEX_ERR_PROTO_MAL && atomic_load_explicit(&ctx->stop, memory_order_relaxed));
    print_standard("mplex reset payload", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_remote_reset_error(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = 10;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    fr.flag = LIBP2P_MPLEX_RESET_INITIATOR;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    uint8_t out[1];
    size_t n = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(ctx, 10, 0, out, sizeof(out), &n);
    int ok = (rc == LIBP2P_MPLEX_ERR_RESET && n == 0);
    print_standard("mplex remote reset error", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_stream_id_limit(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    libp2p_mplex_frame_t fr = {0};
    fr.id = ((uint64_t)1 << 60);
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_dispatch_frame(ctx, &fr);
    int ok = (rc == LIBP2P_MPLEX_ERR_PROTO_MAL && atomic_load_explicit(&ctx->stop, memory_order_relaxed));
    print_standard("mplex stream id limit", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_duplicate_stream_id(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    uint64_t sid = 1;
    libp2p_mplex_stream_t *st = calloc(1, sizeof(*st));
    st->id = sid;
    st->initiator = 1;
    st->name = NULL;
    st->name_len = 0;
    ctx->streams.items = malloc(sizeof(st));
    ctx->streams.cap = 1;
    ctx->streams.items[0] = st;
    ctx->streams.len = 1;

    libp2p_mplex_frame_t fr = {0};
    fr.id = sid;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    int have_local = 0, have_remote = 0;
    for (size_t i = 0; i < ctx->streams.len; i++)
    {
        if (ctx->streams.items[i]->id == sid)
        {
            if (ctx->streams.items[i]->initiator)
                have_local = 1;
            else
                have_remote = 1;
        }
    }
    int ok = (ctx->streams.len == 2 && have_local && have_remote);
    print_standard("mplex duplicate stream id", ok ? "" : "", ok);

    libp2p_mplex_ctx_free(ctx);
}

static void test_duplicate_stream_id_io(void)
{
    libp2p_conn_t dummy = {0};
    libp2p_mplex_ctx_t *ctx = libp2p_mplex_ctx_new(&dummy);
    assert(ctx);

    uint64_t sid = 2;
    libp2p_mplex_stream_t *local = calloc(1, sizeof(*local));
    local->id = sid;
    local->initiator = 1;
    local->name = NULL;
    local->name_len = 0;
    ctx->streams.items = malloc(sizeof(local));
    ctx->streams.cap = 1;
    ctx->streams.items[0] = local;
    ctx->streams.len = 1;

    libp2p_mplex_frame_t fr = {0};
    fr.id = sid;
    fr.flag = LIBP2P_MPLEX_NEW_STREAM;
    fr.data = NULL;
    fr.data_len = 0;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    fr.flag = LIBP2P_MPLEX_MSG_INITIATOR;
    fr.data = (uint8_t *)"x";
    fr.data_len = 1;
    assert(libp2p_mplex_dispatch_frame(ctx, &fr) == LIBP2P_MPLEX_OK);

    uint8_t out[2];
    size_t n = 0;
    assert(libp2p_mplex_stream_recv(ctx, sid, 0, out, sizeof(out), &n) == LIBP2P_MPLEX_OK);
    int ok = (n == 1 && out[0] == 'x');
    print_standard("mplex duplicate id io", ok ? "" : "", ok);

    assert(libp2p_mplex_stream_recv(ctx, sid, 1, out, sizeof(out), &n) == LIBP2P_MPLEX_OK && n == 0);

    libp2p_mplex_ctx_free(ctx);
}

int main(void)
{
    test_negotiate_success();
    test_muxer_wrapper();
    test_frame_roundtrip();
    test_helper_functions();
    test_header_varint_too_long();
    test_length_varint_too_long();
    test_ctx_dispatch();
    test_stream_recv_buffer();
    test_process_loop();
    test_process_one();
    test_inbound_stream_queue();
    test_slow_reader_reset();
    test_recv_buffer_limit_reset();
    test_remote_close_eof();
    test_data_after_remote_close();
    test_close_payload();
    test_reset_payload();
    test_remote_reset_error();
    test_stream_id_limit();
    test_duplicate_stream_id();
    test_duplicate_stream_id_io();
    return 0;
}
