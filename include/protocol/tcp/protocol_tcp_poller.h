#ifndef PROTOCOL_TCP_POLLER_H
#define PROTOCOL_TCP_POLLER_H

/*
 *  protocol_tcp_poller.h ― epoll / kqueue accept-loop helpers
 *                          + central TCP transport structs
 */

#include <pthread.h>   /* pthread_t / mutex           */
#include <stdatomic.h> /* atomic_*                    */
#include <stddef.h>    /* size_t                      */
#include <stdint.h>    /* uintptr_t                   */
#include <time.h>      /* clockid_t                   */

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"       /* libp2p_tcp_config_t   */
#include "protocol/tcp/protocol_tcp_queue.h" /* conn_queue_t          */
#include "transport/listener.h"              /* libp2p_listener_t     */

/* Forward‐declare the listener typedef so we can use it below */
typedef struct tcp_listener tcp_listener_ctx_t;

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define USE_KQUEUE 1
#else
#define USE_EPOLL 1
#endif

/* ------------------------------------------------------------------------- */
/*  Transport-wide context                                                   */
/* ------------------------------------------------------------------------- */
struct tcp_transport_ctx
{
    libp2p_tcp_config_t cfg;
    atomic_bool closed;

#if defined(USE_EPOLL)
    int epfd;
#elif defined(USE_KQUEUE)
    int kqfd;
#endif

    pthread_t thr;
    pthread_mutex_t lck;

    libp2p_listener_t **listeners;
    size_t n_listeners;

    /* ─── deferred-free bookkeeping ─────────────────────────────────── */
    pthread_mutex_t graveyard_lck;
    tcp_listener_ctx_t *graveyard_head;
    _Atomic uint64_t poll_epoch;
    _Atomic bool     compact_pending; /* pending listener‑array compaction */
    _Atomic size_t active_listener_destroyers; /* per-transport destroyer counter */
    // Self-wakeup mechanism
    void *wakeup_marker; // unique marker for wakeup events
    _Atomic int wakeup_pipe[2];  // [0]: read end, [1]: write end (atomic ⇒ race‑free)
};

typedef struct tcp_transport_ctx tcp_transport_ctx_t;

/* ------------------------------------------------------------------------- */
/*  Per-listener context                                                     */
/* ------------------------------------------------------------------------- */
struct tcp_listener
{
    _Atomic int fd;   /* atomic ⇒ close/read race‑free */
    multiaddr_t *local;
    atomic_bool closed;
    _Atomic size_t refcount;
    conn_queue_t q;
    struct tcp_transport_ctx *tctx;

    /* ─── deferred-free bookkeeping ─────────────────────────────────── */
    _Atomic bool pending_free;
    struct tcp_listener *next_free;
    _Atomic size_t free_epoch;

    _Atomic bool disabled; /* true  ⇒ not in poll-set   */
    uint64_t enable_at_ms; /* wall-clock when to re-add */
    uint32_t backoff_ms;   /* next delay (100 → 200 …)  */
    uint32_t poll_ms;      /* accept() poll period in ms */
    uint32_t close_timeout_ms; /* listener close timeout in ms */
    /* Clock used with pthread_cond_timedwait in accept() */
    clockid_t cond_clock;

    /* number of threads currently blocked in pthread_cond_(timed)wait() */
    _Atomic size_t waiters;
};

/* ------------------------------------------------------------------------- */
/*  Poller API                                                               */
/* ------------------------------------------------------------------------- */
int poller_add(tcp_transport_ctx_t *tctx, tcp_listener_ctx_t *lctx);
void poller_del(tcp_transport_ctx_t *tctx, tcp_listener_ctx_t *lctx);

/* Thread entry point (used by pthread_create in tcp_transport_new) */
void *poll_loop(void *arg);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_TCP_POLLER_H */