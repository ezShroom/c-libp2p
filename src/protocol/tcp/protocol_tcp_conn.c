#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "protocol/tcp/protocol_tcp_conn.h"
#include "protocol/tcp/protocol_tcp_util.h"

ssize_t tcp_conn_read(libp2p_conn_t *c, void *buf, size_t len)
{
    tcp_conn_ctx_t *ctx = c->ctx;
    if (atomic_load(&ctx->closed))
    {
        return LIBP2P_CONN_ERR_CLOSED;
    }

    /* deadline handling */
    if (ctx->deadline_at > 0)
    {
        uint64_t now = now_mono_ms();
        if (now < ctx->deadline_at)
        {
            int timeout = (int)(ctx->deadline_at - now);
            struct pollfd pfd = {.fd = ctx->fd, .events = POLLIN};
            int r = poll(&pfd, 1, timeout);
            if (r <= 0)
            {
                if (r == 0 || errno == EINTR)
                    return LIBP2P_CONN_ERR_AGAIN;
                return LIBP2P_CONN_ERR_INTERNAL;
            }
        }
        else
        {
            return LIBP2P_CONN_ERR_AGAIN; /* past deadline */
        }
    }

    /* actual read */
#ifdef _WIN32
    ssize_t n = recv((SOCKET)ctx->fd, (char *)buf, (int)len, 0);
    if (n == SOCKET_ERROR)
    {
        int werr = WSAGetLastError();
        if (werr == WSAEWOULDBLOCK)
            return LIBP2P_CONN_ERR_AGAIN;
        return LIBP2P_CONN_ERR_INTERNAL;
    }
#else
    ssize_t n = read(ctx->fd, buf, len);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBP2P_CONN_ERR_AGAIN;
        return LIBP2P_CONN_ERR_INTERNAL;
    }
#endif

    if (n == 0)
    {
        return LIBP2P_CONN_ERR_EOF;
    }
    return n;
}

ssize_t tcp_conn_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    tcp_conn_ctx_t *ctx = c->ctx;
    if (atomic_load(&ctx->closed))
    {
        return LIBP2P_CONN_ERR_CLOSED;
    }

    /* deadline handling */
    if (ctx->deadline_at > 0)
    {
        uint64_t now = now_mono_ms();
        if (now < ctx->deadline_at)
        {
            int timeout = (int)(ctx->deadline_at - now);
            struct pollfd pfd = {.fd = ctx->fd, .events = POLLOUT};
            int r = poll(&pfd, 1, timeout);
            if (r <= 0)
            {
                if (r == 0 || errno == EINTR)
                    return LIBP2P_CONN_ERR_AGAIN;
                return LIBP2P_CONN_ERR_INTERNAL;
            }
        }
        else
        {
            return LIBP2P_CONN_ERR_AGAIN; /* past deadline */
        }
    }

    /* actual write */
#ifdef _WIN32
    ssize_t n = send((SOCKET)ctx->fd, (const char *)buf, (int)len, 0);
    if (n == SOCKET_ERROR)
    {
        int werr = WSAGetLastError();
        if (werr == WSAEWOULDBLOCK)
            return LIBP2P_CONN_ERR_AGAIN;
        return LIBP2P_CONN_ERR_INTERNAL;
    }
#else
    ssize_t n = write(ctx->fd, buf, len);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return LIBP2P_CONN_ERR_AGAIN;
        return LIBP2P_CONN_ERR_INTERNAL;
    }
#endif
    return n;
}

libp2p_conn_err_t tcp_conn_set_deadline(libp2p_conn_t *c, uint64_t ms)
{
    tcp_conn_ctx_t *ctx = c->ctx;
    ctx->deadline_at = (ms == 0) ? 0 : now_mono_ms() + ms;
    return LIBP2P_CONN_OK;
}

const multiaddr_t *tcp_conn_local(libp2p_conn_t *c)
{
    if (!c)
    {
        return NULL;
    }
    if (!c->ctx)
    {
        return NULL;
    }

    return ((tcp_conn_ctx_t *)c->ctx)->local;
}
const multiaddr_t *tcp_conn_remote(libp2p_conn_t *c)
{
    if (!c)
    {
        return NULL;
    }
    if (!c->ctx)
    {
        return NULL;
    }

    return ((tcp_conn_ctx_t *)c->ctx)->remote;
}

libp2p_conn_err_t tcp_conn_close(libp2p_conn_t *c)
{
    if (!c)
    {
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    if (!c->ctx)
    {
        return LIBP2P_CONN_ERR_INTERNAL;
    }

    tcp_conn_ctx_t *ctx = c->ctx;
    if (atomic_load(&ctx->closed))
    {
        return LIBP2P_CONN_ERR_CLOSED;
    }

    atomic_store(&ctx->closed, true);
    shutdown(ctx->fd, SHUT_RDWR);
    close(ctx->fd);
    return LIBP2P_CONN_OK;
}

void tcp_conn_free(libp2p_conn_t *c)
{
    if (!c)
    {
        return;
    }

    tcp_conn_ctx_t *ctx = c->ctx;
    if (ctx)
    {
        if (!atomic_load(&ctx->closed))
        {
            close(ctx->fd);
        }

        multiaddr_free(ctx->local);
        multiaddr_free(ctx->remote);
        free(ctx);
    }
    free(c);
}

const libp2p_conn_vtbl_t TCP_CONN_VTBL = {
    .read = tcp_conn_read,
    .write = tcp_conn_write,
    .set_deadline = tcp_conn_set_deadline,
    .local_addr = tcp_conn_local,
    .remote_addr = tcp_conn_remote,
    .close = tcp_conn_close,
    .free = tcp_conn_free,
};

libp2p_conn_t *make_tcp_conn(int fd)
{
    /* ensure non-blocking ― may already be, but call for good measure.      */
    if (set_nonblocking(fd) == -1)
    {
        close(fd);
        return NULL;
    }

    /* gather local / peer addresses */
    struct sockaddr_storage lss = {0}, rss = {0};
    socklen_t llen = sizeof lss, rlen = sizeof rss;

    if (getsockname(fd, (struct sockaddr *)&lss, &llen) != 0)
    {
        close(fd);
        return NULL;
    }

    bool have_peer = (getpeername(fd, (struct sockaddr *)&rss, &rlen) == 0);

    /* allocate context */
    tcp_conn_ctx_t *ctx = calloc(1, sizeof *ctx);
    if (!ctx)
    {
        close(fd);
        return NULL;
    }
    ctx->fd = fd;

    /* local multiaddr */
    ctx->local = sockaddr_to_multiaddr(&lss, llen);
    if (!ctx->local)
    {
        free(ctx);
        close(fd);
        return NULL;
    }

    /* remote multiaddr (optional) */
    if (have_peer)
    {
        ctx->remote = sockaddr_to_multiaddr(&rss, rlen);
        if (!ctx->remote)
        {
            multiaddr_free(ctx->local);
            free(ctx);
            close(fd);
            return NULL;
        }
    }

    /* wrap into libp2p_conn_t */
    libp2p_conn_t *c = calloc(1, sizeof *c);
    if (!c)
    {
        multiaddr_free(ctx->local);
        multiaddr_free(ctx->remote);
        free(ctx);
        close(fd);
        return NULL;
    }

    c->vt = &TCP_CONN_VTBL;
    c->ctx = ctx;
    return c;
}
