#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol/tcp/protocol_tcp_poller.h"
#include "protocol/tcp/protocol_tcp_queue.h"
#include "protocol/tcp/protocol_tcp_util.h"

/* transient resource‑exhaustion errors we back‑off on */
#define TRANSIENT_ERR(e) ((e) == EMFILE || (e) == ENFILE || (e) == ENOBUFS)

/* Maximum number of unconsumed accepted connections per listener */
#define ACCEPT_QUEUE_MAX 1024
#define MAX_ACCEPT_PER_LOOP 32

#if defined(USE_KQUEUE)
#include <sys/event.h> /* struct kevent, EV_SET, kevent()       */
#elif defined(USE_EPOLL)
#include <sys/epoll.h> /* struct epoll_event, epoll_*()         */
#endif


int poller_add(struct tcp_transport_ctx *tctx, tcp_listener_ctx_t *lctx)
{
#if USE_EPOLL
    struct epoll_event ev;
    ev.events = EPOLLIN
#ifdef EPOLLEXCLUSIVE
                | EPOLLEXCLUSIVE
#endif
        ;
    ev.data.ptr = lctx;
    return epoll_ctl(tctx->epfd, EPOLL_CTL_ADD, lctx->fd, &ev);
#elif USE_KQUEUE
    struct kevent kev;
    EV_SET(&kev, lctx->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, lctx);
    return kevent(tctx->kqfd, &kev, 1, NULL, 0, NULL);
#endif
}

void poller_del(struct tcp_transport_ctx *tctx, tcp_listener_ctx_t *lctx)
{
#if USE_EPOLL
    epoll_ctl(tctx->epfd, EPOLL_CTL_DEL, lctx->fd, NULL);
#elif USE_KQUEUE
    struct kevent kev;
    EV_SET(&kev, lctx->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(tctx->kqfd, &kev, 1, NULL, 0, NULL);
#endif
}

static void destroy_listener_ctx(tcp_listener_ctx_t *ctx)
{
    /* finally safe to close the fd */
    close(ctx->fd);

    libp2p_conn_t *c;
    while ((c = cq_pop(&ctx->q)))
    {
        libp2p_conn_free(c);
    }
    pthread_cond_destroy(&ctx->q.cond);
    pthread_mutex_destroy(&ctx->q.mtx);
    multiaddr_free(ctx->local);
    free(ctx);
}

static inline void release_listener_ref(tcp_listener_ctx_t *lctx)
{
    /* ensure decrement and signal are under the same mutex to prevent lost wakeups */
    pthread_mutex_lock(&lctx->q.mtx);
    unsigned old = atomic_fetch_sub_explicit(&lctx->refcount, 1, memory_order_release);
    assert(old >= 1);
    if (old == 2)
    {
        pthread_cond_signal(&lctx->q.cond);
    }
    pthread_mutex_unlock(&lctx->q.mtx);
}

void *poll_loop(void *arg)
{
    tcp_transport_ctx_t *tctx = arg;

#if USE_EPOLL
    struct epoll_event evs[64];
#elif defined(USE_KQUEUE)
    struct kevent evs[64];
#endif

    while (!atomic_load_explicit(&tctx->closed, memory_order_acquire))
    {
        /* wait up to 200 ms for new readiness events */
#if defined(USE_EPOLL)
        int n = epoll_wait(tctx->epfd, evs, (int)(sizeof evs / sizeof *evs), 200);
#elif defined(USE_KQUEUE)
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
        int n = kevent(tctx->kqfd, NULL, 0, evs, (int)(sizeof evs / sizeof *evs), &ts);
#endif

        /* improved error handling */
        if (n < 0)
        {
            if (errno == EINTR)
            {
                /* interrupted by signal: treat as timeout/no events */
                n = 0;
            }
            else
            {
#if defined(USE_EPOLL)
                perror("poll_loop: epoll_wait failed");
#elif defined(USE_KQUEUE)
                perror("poll_loop: kevent failed");
#endif
                /* still treat as no events to avoid busy-looping */
                n = 0;
            }
        }

        /* handle the batch of ready listeners */
        for (int i = 0; i < n; ++i)
        {
#if defined(USE_EPOLL)
            // Check for self-wakeup event
            if (evs[i].data.ptr == tctx)
            {
                char buf[64];
                {
                    ssize_t r;
                    do
                    {
                        r = read(tctx->wakeup_pipe[0], buf, sizeof(buf));
                    } while (r > 0);
                    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        perror("poll_loop: draining wakeup pipe failed");
                    }
                }
                continue;
            }
            if (evs[i].data.ptr == NULL)
            {
                continue;
            }

            tcp_listener_ctx_t *lctx = (tcp_listener_ctx_t *)evs[i].data.ptr;
#elif defined(USE_KQUEUE)
            /* check for self-wakeup event */
            if (evs[i].udata == tctx)
            {
                char buf[64];
                {
                    ssize_t r;
                    do
                    {
                        r = read(tctx->wakeup_pipe[0], buf, sizeof(buf));
                    } while (r > 0);
                    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        perror("poll_loop: draining wakeup pipe failed");
                    }
                }
                continue;
            }

            if (evs[i].udata == NULL)
            {
                continue;
            }
            tcp_listener_ctx_t *lctx = (tcp_listener_ctx_t *)evs[i].udata;
#endif

            /* grab a temporary reference *before* inspecting any fields */
            atomic_fetch_add_explicit(&lctx->refcount, 1, memory_order_acq_rel);

            if (atomic_load_explicit(&lctx->closed, memory_order_acquire) || atomic_load_explicit(&lctx->pending_free, memory_order_acquire))
            {
                goto done_listener;
            }

            /* inside poll_loop(), in the accept batch */
            int accept_count = 0;
            while (accept_count < MAX_ACCEPT_PER_LOOP)
            {
                /* backpressure: stop accepting when the queue is full */
                if (atomic_load_explicit(&lctx->q.len, memory_order_relaxed) >= ACCEPT_QUEUE_MAX)
                {
                    break; /* defer further accepts until consumer drains the queue */
                }
                int fd;
#if defined(__linux__) && defined(SOCK_CLOEXEC)
                fd = accept4(lctx->fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
                fd = accept(lctx->fd, NULL, NULL);
                if (fd >= 0)
                {
                    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1 || set_nonblocking(fd) == -1)
                    {
                        close(fd);

                        /* fall through: stop processing this listener for now */
                        goto done_listener;
                    }
                }
#endif
                if (fd < 0)
                {
                    int err = errno;
                    if (err == EAGAIN || err == EWOULDBLOCK)
                    {
                        break; /* backlog drained */
                    }

                    /* temporary back‑off on resource exhaustion */
                    if (TRANSIENT_ERR(err) && !atomic_load_explicit(&lctx->disabled, memory_order_acquire))
                    {
                        atomic_store_explicit(&lctx->disabled, true, memory_order_release);
                        pthread_cond_broadcast(&lctx->q.cond);
                        lctx->enable_at_ms = now_mono_ms() + lctx->backoff_ms;
                        if (lctx->backoff_ms < 10 * 1000)
                        {
                            lctx->backoff_ms <<= 1; /* exponential back‑off */
                        }

                        poller_del(tctx, lctx); /* remove from poll set */
                    }

                    /* fall through: stop processing this listener for now */
                    goto done_listener;
                }

                accept_count++;

                /* TCP_NODELAY */
                if (lctx->tctx->cfg.nodelay)
                {
                    int on = 1;
                    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0)
                    {
                        close(fd);
                        continue;
                    }
                }

                /* SO_KEEPALIVE */
                if (lctx->tctx->cfg.keepalive)
                {
                    int on = 1;
                    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
                    {
                        close(fd);
                        continue;
                    }
                }

                /* build our libp2p_conn_t wrapper */
                libp2p_conn_t *c = make_tcp_conn(fd);
                if (c == NULL)
                {
                    /* allocation failed — ensure we close the socket and
                    immediately retry accepting the next one */
                    close(fd);
                    continue;
                }

                /* only enqueue if the listener is still open */
                if (!atomic_load_explicit(&lctx->closed, memory_order_acquire))
                {
                    cq_push(&lctx->q, c);
                }
                else
                {
                    libp2p_conn_free(c);
                }
            }

            /* end accept loop */
        done_listener:
            release_listener_ref(lctx);
            continue;
        }

        /* try to re‑enable listeners after back‑off */
        uint64_t now = now_mono_ms();
        pthread_mutex_lock(&tctx->lck);
        for (size_t j = 0; j < tctx->n_listeners; ++j)
        {
            libp2p_listener_t *pub = tctx->listeners[j];
            if (!pub)
            {
                continue;
            }
            tcp_listener_ctx_t *l = (tcp_listener_ctx_t *)pub->ctx;
            if (atomic_load_explicit(&l->disabled, memory_order_acquire) && now >= l->enable_at_ms)
            {
                if (poller_add(tctx, l) == 0)
                {
                    atomic_store_explicit(&l->disabled, false, memory_order_release);
                }
                else
                {
                    l->enable_at_ms = now + l->backoff_ms;
                    if (l->backoff_ms < 10 * 1000)
                        l->backoff_ms <<= 1;
                }
            }
        }
        pthread_mutex_unlock(&tctx->lck);

        /* advance epoch and reap deferred-free listeners */
        uint64_t my_epoch = atomic_fetch_add(&tctx->poll_epoch, 1) + 1;

        pthread_mutex_lock(&tctx->graveyard_lck);
        tcp_listener_ctx_t **pp = &tctx->graveyard_head;
        while (*pp)
        {
            tcp_listener_ctx_t *victim = *pp;

            if (atomic_load_explicit(&victim->refcount, memory_order_acquire) == 0 && victim->free_epoch <= my_epoch)
            {
                /* unlink from graveyard list */
                *pp = victim->next_free;
                pthread_mutex_unlock(&tctx->graveyard_lck);

                destroy_listener_ctx(victim);

                /* re-lock and continue scanning from head */
                pthread_mutex_lock(&tctx->graveyard_lck);
                continue;
            }
            pp = &(*pp)->next_free;
        }
        pthread_mutex_unlock(&tctx->graveyard_lck);
    }

    return NULL;
}