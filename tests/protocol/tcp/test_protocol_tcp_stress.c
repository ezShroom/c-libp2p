/*  ──────────────────────────────────────────────────────────────── *\
    c-libp2p TCP transport – high-load stress / race harness
\*  ──────────────────────────────────────────────────────────────── */

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <stdatomic.h>

#define DEFAULT_N_THREADS 1
#define DEFAULT_ITER_PER_THREAD 1

/* Poll/read retry parameters – Windows loopback can be noticeably
   slower to deliver data after an accept() than Linux/macOS.
   Allow more retries with a slightly longer back-off so the harness
   remains reliable across platforms while still finishing quickly. */
#ifndef READ_RETRIES
#define READ_RETRIES 100 /* total wait ≈ READ_RETRIES * READ_SLEEP_US */
#endif
#ifndef READ_SLEEP_US
#define READ_SLEEP_US 1000 /* 1 ms */
#endif

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

/* ------------------------------ tunables ------------------------------ */
#ifndef PAYLOAD_SZ
#define PAYLOAD_SZ 64
#endif

typedef struct
{
    libp2p_transport_t *tcp;
    multiaddr_t *addr;
    int iter_per_thread;
    atomic_int failures;
} harness_ctx_t;

/* ---- runtime‑tunable knobs via environment ------------------------ */
static inline int env_int_or(const char *name, int def)
{
    const char *s = getenv(name);
    if (!s || *s == '\0')
        return def;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end && *end == '\0' && v > 0 && v <= INT_MAX)
        return (int)v;
    return def; /* fallback on parse error / out‑of‑range */
}

/* --------------------------------------------------------------------- */
/* Output helpers (uniform test harness style)                           */
/* --------------------------------------------------------------------- */

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-70s | PASS\n", test_name);
    else
        printf("TEST: %-70s | FAIL: %s\n", test_name, details);
}

/* --------------------------------------------------------------------- */
/* dialer worker: repeatedly dial, send/recv, close                      */
/* --------------------------------------------------------------------- */
static void *dialer_worker(void *arg)
{
    harness_ctx_t *h = arg;
    uint8_t ping[PAYLOAD_SZ];
    memset(ping, 0xA5, sizeof ping);

    for (int i = 0; i < h->iter_per_thread; ++i)
    {
        libp2p_conn_t *c = NULL;
        if (libp2p_transport_dial(h->tcp, h->addr, &c) != 0 || !c)
        {
            atomic_fetch_add_explicit(&h->failures, 1, memory_order_relaxed);
            continue;
        }

        /* send payload, expect echo-back */
        if (libp2p_conn_write(c, ping, sizeof ping) != sizeof ping)
        {
            atomic_fetch_add_explicit(&h->failures, 1, memory_order_relaxed);
            libp2p_conn_close(c);
            libp2p_conn_free(c);
            continue;
        }

        uint8_t buf[PAYLOAD_SZ] = {0};
        ssize_t n = LIBP2P_CONN_ERR_AGAIN;
        for (int j = 0; j < READ_RETRIES && n == LIBP2P_CONN_ERR_AGAIN; ++j)
        {
            n = libp2p_conn_read(c, buf, sizeof buf);
            if (n == LIBP2P_CONN_ERR_AGAIN)
                usleep(READ_SLEEP_US);
        }
        if (n != sizeof ping || memcmp(buf, ping, sizeof ping) != 0)
            atomic_fetch_add_explicit(&h->failures, 1, memory_order_relaxed);

        libp2p_conn_close(c);
        libp2p_conn_free(c);
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
/* server-side accept/echo loop (runs in its own thread)                 */
/* --------------------------------------------------------------------- */
static void *echo_server(void *arg)
{
    libp2p_listener_t *l = arg;
    for (;;)
    {
        libp2p_conn_t *c = NULL;
        libp2p_listener_err_t rc = l->vt->accept(l, &c);
        if (rc == LIBP2P_LISTENER_ERR_CLOSED)
            break;
        if (rc != LIBP2P_LISTENER_OK || !c)
            continue;

        uint8_t buf[PAYLOAD_SZ] = {0};
        ssize_t n = LIBP2P_CONN_ERR_AGAIN;
        for (int j = 0; j < READ_RETRIES && n == LIBP2P_CONN_ERR_AGAIN; ++j)
        {
            n = libp2p_conn_read(c, buf, sizeof buf);
            if (n == LIBP2P_CONN_ERR_AGAIN)
                usleep(READ_SLEEP_US);
        }
        if (n == (ssize_t)sizeof buf)
            (void)libp2p_conn_write(c, buf, sizeof buf);

        libp2p_conn_close(c);
        libp2p_conn_free(c);
    }
    return NULL;
}

/* --------------------------------------------------------------------- */
int main(void)
{
    srand((unsigned)time(NULL));

    /* -------- create transport -------- */
    libp2p_tcp_config_t cfg = libp2p_tcp_config_default();
    cfg.accept_poll_ms = 10;       /* wake listener every 10 ms        */
    cfg.connect_timeout_ms = 5000; /* 5 s dial timeout                 */
    /* Use default close_timeout_ms to avoid premature forced close */
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(&cfg);
    if (!tcp)
    {
        fprintf(stderr, "transport new failed\n");
        return 1;
    }

    /* -------- pick random port -------- */
    int port = 7000 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof addr_str, "/ip4/127.0.0.1/tcp/%d", port);

    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str(addr_str, &err);
    if (!ma || err)
    {
        fprintf(stderr, "addr parse fail\n");
        return 1;
    }

    /* -------- runtime knobs -------- */
    int n_threads = env_int_or("STRESS_THREADS", DEFAULT_N_THREADS);
    int iter_per_thread = env_int_or("STRESS_ITERS", DEFAULT_ITER_PER_THREAD);

    /* -------- listen -------- */
    libp2p_listener_t *lst = NULL;
    if (tcp->vt->listen(tcp, ma, &lst) != 0)
    {
        fprintf(stderr, "listen failed\n");
        return 1;
    }

    /* -------- launch echo server thread -------- */
    pthread_t srv_thr;
    pthread_create(&srv_thr, NULL, echo_server, lst);

    /* -------- launch N dialer threads -------- */
    harness_ctx_t ctx = {
        .tcp = tcp,
        .addr = ma,
        .iter_per_thread = iter_per_thread,
    };
    atomic_init(&ctx.failures, 0);

    pthread_t *dial_thr = calloc(n_threads, sizeof *dial_thr);
    if (!dial_thr)
    {
        perror("calloc");
        return 1;
    }
    for (int i = 0; i < n_threads; ++i)
        pthread_create(&dial_thr[i], NULL, dialer_worker, &ctx);

    /* -------- wait for dialers -------- */
    for (int i = 0; i < n_threads; ++i)
        pthread_join(dial_thr[i], NULL);
    free(dial_thr);

    /* -------- shut down listener & server -------- */
    libp2p_listener_close(lst); /* ensures server thread wakes and exits */

    /* always wait for the echo‑server thread to finish */
    pthread_join(srv_thr, NULL);

    /* Listener will be cleaned up when the transport is freed */

    /* -------- cleanup -------- */
    multiaddr_free(ma);
    /* Always shut the transport down cleanly so that no allocations remain
       outstanding when the process exits, even in quick smoke‑test runs. */
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp); /* full, blocking shutdown */

    int fails = atomic_load_explicit(&ctx.failures, memory_order_relaxed);

    if (fails == 0)
    {
        print_standard("TCP stress harness", "", 1);
    }
    else
    {
        char details[64];
        snprintf(details, sizeof details, "%d failures", fails);
        print_standard("TCP stress harness", details, 0);
    }

    return (fails == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}