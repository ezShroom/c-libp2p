#include "protocol/mplex/protocol_mplex.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/mplex/protocol_mplex_codec.h"
#include "protocol/mplex/protocol_mplex_handshake.h"
#include "protocol/mplex/protocol_mplex_queue.h"
#include "protocol/protocol_handler.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include "transport/conn_util.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Map a connection layer error to an mplex specific error code.
 *
 * @param v Error returned from the connection API.
 * @return Equivalent mplex error value.
 */
static inline libp2p_mplex_err_t map_conn_err(ssize_t v)
{
    switch ((libp2p_conn_err_t)v)
    {
        case LIBP2P_CONN_ERR_TIMEOUT:
            return LIBP2P_MPLEX_ERR_HANDSHAKE;
        case LIBP2P_CONN_ERR_AGAIN:
        case LIBP2P_CONN_ERR_EOF:
        case LIBP2P_CONN_ERR_CLOSED:
        case LIBP2P_CONN_ERR_INTERNAL:
        default:
            return LIBP2P_MPLEX_ERR_INTERNAL;
    }
}

/*
 * Remove a stream from the context if both sides are done with it or it was
 * reset. This keeps the stream list from growing unbounded.
 */
static void maybe_cleanup_stream(libp2p_mplex_ctx_t *ctx, size_t idx);

/**
 * @brief Write the entire buffer with a soft timeout.
 *
 * Retries short writes and waits briefly when the connection would block so
 * that the processing loop does not stall indefinitely on slow connections.
 *
 * @param c   Connection to send on.
 * @param buf Data buffer to write.
 * @param len Number of bytes to send.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
static libp2p_mplex_err_t conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    libp2p_conn_err_t rc = libp2p_conn_write_all(c, buf, len, 1000);
    return (rc == LIBP2P_CONN_OK) ? LIBP2P_MPLEX_OK : map_conn_err(rc);
}

/**
 * @brief Read exactly @p len bytes from a connection.
 *
 * Any connection error is translated into the appropriate mplex error code.
 *
 * @param c   Connection to read from.
 * @param buf Buffer to fill.
 * @param len Number of bytes to read.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
static libp2p_mplex_err_t conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
{
    libp2p_conn_err_t rc = libp2p_conn_read_exact(c, buf, len);
    return (rc == LIBP2P_CONN_OK) ? LIBP2P_MPLEX_OK : map_conn_err(rc);
}

/**
 * @brief Wrapper that negotiates the mplex protocol for outbound connections.
 */
static libp2p_muxer_err_t mplex_negotiate_out(libp2p_muxer_t *self, libp2p_conn_t *c, uint64_t to)
{
    (void)self;
    libp2p_mplex_err_t mplex_err = libp2p_mplex_negotiate_outbound(c, to);

    // Convert mplex-specific error codes to generic muxer error codes
    switch (mplex_err)
    {
        case LIBP2P_MPLEX_OK:
            return LIBP2P_MUXER_OK;
        case LIBP2P_MPLEX_ERR_NULL_PTR:
            return LIBP2P_MUXER_ERR_NULL_PTR;
        case LIBP2P_MPLEX_ERR_HANDSHAKE:
            return LIBP2P_MUXER_ERR_HANDSHAKE;
        default:
            return LIBP2P_MUXER_ERR_INTERNAL;
    }
}

/**
 * @brief Wrapper that negotiates the mplex protocol for inbound connections.
 */
static libp2p_muxer_err_t mplex_negotiate_in(libp2p_muxer_t *self, libp2p_conn_t *c, uint64_t to)
{
    (void)self;
    libp2p_mplex_err_t mplex_err = libp2p_mplex_negotiate_inbound(c, to);

    // Convert mplex-specific error codes to generic muxer error codes
    switch (mplex_err)
    {
        case LIBP2P_MPLEX_OK:
            return LIBP2P_MUXER_OK;
        case LIBP2P_MPLEX_ERR_NULL_PTR:
            return LIBP2P_MUXER_ERR_NULL_PTR;
        case LIBP2P_MPLEX_ERR_HANDSHAKE:
            return LIBP2P_MUXER_ERR_HANDSHAKE;
        default:
            return LIBP2P_MUXER_ERR_INTERNAL;
    }
}

/**
 * @brief Close a muxer instance (no-op for mplex).
 */
static libp2p_muxer_err_t mplex_close(libp2p_muxer_t *self)
{
    (void)self;
    return LIBP2P_MUXER_OK;
}

/**
 * @brief Free a muxer instance allocated with ::libp2p_mplex_new.
 */
static void mplex_free(libp2p_muxer_t *self) { free(self); }

static int mplex_negotiate(libp2p_muxer_t *mx, libp2p_conn_t *c, uint64_t to, bool inbound)
{
    return inbound ? mplex_negotiate_in(mx, c, to) : mplex_negotiate_out(mx, c, to);
}

static int mplex_open_stream(libp2p_muxer_t *mx, const uint8_t *name, size_t name_len, libp2p_stream_t **out)
{
    if (!mx || !mx->ctx || !out)
        return LIBP2P_MUXER_ERR_NULL_PTR;
    uint64_t id;
    if (libp2p_mplex_stream_open(mx->ctx, name, name_len, &id) != LIBP2P_MPLEX_OK)
        return LIBP2P_MUXER_ERR_INTERNAL;
    libp2p_stream_t *s = calloc(1, sizeof(*s));
    if (!s)
        return LIBP2P_MUXER_ERR_INTERNAL;
    s->uconn = NULL;
    s->stream_id = id;
    s->initiator = 1;
    s->protocol_id = NULL;
    s->ctx = mx->ctx;
    *out = s;
    return LIBP2P_MUXER_OK;
}

static ssize_t mplex_stream_read(libp2p_stream_t *s, void *buf, size_t len)
{
    if (!s || !buf)
        return -1;
    size_t out_len = 0;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(s->ctx, s->stream_id, s->initiator, buf, len, &out_len);
    if (rc == LIBP2P_MPLEX_OK)
        return (ssize_t)out_len;
    if (rc == LIBP2P_MPLEX_ERR_EOF)
        return 0;
    return -1;
}

static ssize_t mplex_stream_write(libp2p_stream_t *s, const void *buf, size_t len)
{
    if (!s || !buf)
        return -1;
    libp2p_mplex_err_t rc = libp2p_mplex_stream_send(s->ctx, s->stream_id, s->initiator, buf, len);
    return rc == LIBP2P_MPLEX_OK ? (ssize_t)len : -1;
}

static void mplex_stream_close(libp2p_stream_t *s)
{
    if (!s)
        return;
    libp2p_mplex_stream_close(s->ctx, s->stream_id, s->initiator);
}

static const libp2p_muxer_vtbl_t MPLEX_VTBL = {
    .negotiate = mplex_negotiate,
    .open_stream = mplex_open_stream,
    .stream_read = mplex_stream_read,
    .stream_write = mplex_stream_write,
    .stream_close = mplex_stream_close,
    .free = mplex_free,
};

/**
 * @brief Allocate and initialize a new mplex muxer object.
 *
 * @return Pointer to the new muxer or NULL on allocation failure.
 */
libp2p_muxer_t *libp2p_mplex_new(void)
{
    libp2p_muxer_t *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    m->vt = &MPLEX_VTBL;
    m->ctx = NULL;
    return m;
}

/**
 * @brief Locate a stream by identifier and initiator flag.
 *
 * @param ctx       Mplex context containing the stream array.
 * @param id        Stream identifier to search for.
 * @param initiator Initiator flag of the stream.
 * @param idx       Optional index output for the found stream.
 * @return Pointer to the stream or NULL if not found.
 */
static libp2p_mplex_stream_t *find_stream(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator, size_t *idx)
{
    if (!ctx)
        return NULL;
    for (size_t i = 0; i < ctx->streams.len; i++)
    {
        if (ctx->streams.items[i]->id == id && ctx->streams.items[i]->initiator == initiator)
        {
            if (idx)
                *idx = i;
            return ctx->streams.items[i];
        }
    }
    return NULL;
}

/**
 * @brief Create a new mplex context bound to a connection.
 *
 * @param conn Underlying connection handle.
 * @return Pointer to a new context or NULL on allocation failure.
 */
libp2p_mplex_ctx_t *libp2p_mplex_ctx_new(libp2p_conn_t *conn)
{
    if (!conn)
        return NULL;
    libp2p_mplex_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->conn = conn;
    ctx->next_stream_id = 1;
    libp2p_mplex_queue_init(&ctx->incoming);
    mplex_stream_array_init(&ctx->streams);
    atomic_init(&ctx->stop, false);
    pthread_mutex_init(&ctx->mtx, NULL);
    return ctx;
}

/**
 * @brief Destroy an mplex context and free all associated resources.
 *
 * @param ctx Context to free.
 */
void libp2p_mplex_ctx_free(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return;
    for (size_t i = 0; i < ctx->streams.len; i++)
    {
        free(ctx->streams.items[i]->buf);
        free(ctx->streams.items[i]->name);
        free(ctx->streams.items[i]);
    }
    mplex_stream_array_free(&ctx->streams);
    while (libp2p_mplex_queue_pop(&ctx->incoming))
        ;
    pthread_mutex_destroy(&ctx->incoming.mtx);
    pthread_cond_destroy(&ctx->incoming.cond);
    pthread_mutex_destroy(&ctx->mtx);
    free(ctx);
}

/**
 * @brief Open a new logical stream within an mplex context.
 *
 * @param ctx      Active mplex context.
 * @param name     Optional stream name.
 * @param name_len Length of the name buffer.
 * @param out_id   Receives the identifier of the new stream.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
libp2p_mplex_err_t libp2p_mplex_stream_open(libp2p_mplex_ctx_t *ctx, const uint8_t *name, size_t name_len, uint64_t *out_id)
{
    if (!ctx || !out_id)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    pthread_mutex_lock(&ctx->mtx);
    if (ctx->next_stream_id >= MPLEX_MAX_STREAM_ID)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }

    uint64_t id = ctx->next_stream_id++;
    libp2p_mplex_err_t rc = libp2p_mplex_open_stream(ctx->conn, id, name, name_len);
    if (rc)
    {
        ctx->next_stream_id--; /* rollback */
        pthread_mutex_unlock(&ctx->mtx);
        return rc;
    }
    libp2p_mplex_stream_t *st = calloc(1, sizeof(*st));
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }
    st->id = id;
    st->initiator = 1;
    if (name_len)
    {
        st->name = malloc(name_len);
        if (!st->name)
        {
            free(st);
            pthread_mutex_unlock(&ctx->mtx);
            return LIBP2P_MPLEX_ERR_INTERNAL;
        }
        memcpy(st->name, name, name_len);
        st->name_len = name_len;
    }
    else
    {
        st->name = NULL;
        st->name_len = 0;
    }
    if (!mplex_stream_array_push(&ctx->streams, st))
    {
        free(st->name);
        free(st);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_INTERNAL;
    }
    *out_id = id;
    pthread_mutex_unlock(&ctx->mtx);
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Send data on an existing mplex stream.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Initiator flag for the stream.
 * @param data      Buffer containing the payload.
 * @param data_len  Size of the payload in bytes.
 */
libp2p_mplex_err_t libp2p_mplex_stream_send(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator, const uint8_t *data, size_t data_len)
{
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_mplex_stream_t *st = find_stream(ctx, id, initiator, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    if (st->reset)
    {
        maybe_cleanup_stream(ctx, idx);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_RESET;
    }
    if (st->local_closed)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    int init = st->initiator;
    pthread_mutex_unlock(&ctx->mtx);
    libp2p_mplex_err_t rc = libp2p_mplex_send_msg(ctx->conn, id, init, data, data_len);
    if (rc == LIBP2P_MPLEX_ERR_TIMEOUT)
    {
        (void)libp2p_mplex_stream_reset(ctx, id, initiator);
    }
    return rc;
}

/**
 * @brief Receive data from an mplex stream without blocking.
 *
 * Copies at most @p max_len bytes into @p buf and reports the number of bytes
 * placed there. If no data is available and the stream is still open, zero is
 * returned.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Initiator flag.
 * @param buf       Destination buffer.
 * @param max_len   Capacity of @p buf.
 * @param out_len   Receives the number of bytes written.
 */
libp2p_mplex_err_t libp2p_mplex_stream_recv(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator, uint8_t *buf, size_t max_len, size_t *out_len)
{
    if (!ctx || !buf || !out_len)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_mplex_stream_t *st = find_stream(ctx, id, initiator, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    if (st->reset)
    {
        maybe_cleanup_stream(ctx, idx);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_RESET;
    }
    size_t avail = st->buf_len > st->buf_pos ? st->buf_len - st->buf_pos : 0;
    if (avail == 0)
    {
        *out_len = 0;
        if (st->remote_closed)
        {
            pthread_mutex_unlock(&ctx->mtx);
            return LIBP2P_MPLEX_ERR_EOF;
        }
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_OK;
    }
    size_t n = max_len < avail ? max_len : avail;
    memcpy(buf, st->buf + st->buf_pos, n);
    st->buf_pos += n;
    if (st->buf_pos == st->buf_len)
    {
        free(st->buf);
        st->buf = NULL;
        st->buf_len = st->buf_pos = 0;
    }
    *out_len = n;
    pthread_mutex_unlock(&ctx->mtx);
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Free resources for a stream when it is no longer active.
 *
 * Called whenever a stream might be removable. Resources are freed once both
 * directions are closed or a reset has occurred.
 *
 * @param ctx Context owning the stream list.
 * @param idx Index of the stream within the array.
 */
static void maybe_cleanup_stream(libp2p_mplex_ctx_t *ctx, size_t idx)
{
    libp2p_mplex_stream_t *st = ctx->streams.items[idx];
    if ((st->local_closed && st->remote_closed) || st->reset)
    {
        mplex_stream_array_remove(&ctx->streams, idx);
        free(st->buf);
        free(st->name);
        free(st);
    }
}

/**
 * @brief Handle a protocol violation by closing the connection and stopping.
 *
 * @param ctx Context associated with the violation.
 * @return LIBP2P_MPLEX_ERR_PROTO_MAL always.
 */
static libp2p_mplex_err_t proto_violation(libp2p_mplex_ctx_t *ctx)
{
    if (ctx && ctx->conn)
        libp2p_conn_close(ctx->conn);
    if (ctx)
        libp2p_mplex_stop(ctx);
    return LIBP2P_MPLEX_ERR_PROTO_MAL;
}

/**
 * @brief Close the local side of a stream and notify the peer.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Initiator flag for the stream.
 */
libp2p_mplex_err_t libp2p_mplex_stream_close(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator)
{
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_mplex_stream_t *st = find_stream(ctx, id, initiator, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    if (st->reset)
    {
        maybe_cleanup_stream(ctx, idx);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_RESET;
    }
    if (st->local_closed)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    int init = st->initiator;
    pthread_mutex_unlock(&ctx->mtx);
    libp2p_mplex_err_t rc = libp2p_mplex_close_stream(ctx->conn, id, init);
    if (rc)
        return rc;
    pthread_mutex_lock(&ctx->mtx);
    st = find_stream(ctx, id, initiator, &idx);
    if (st)
    {
        st->local_closed = 1;
        maybe_cleanup_stream(ctx, idx);
    }
    pthread_mutex_unlock(&ctx->mtx);
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Forcefully reset a stream.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Initiator flag for the stream.
 */
libp2p_mplex_err_t libp2p_mplex_stream_reset(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator)
{
    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_mplex_stream_t *st = find_stream(ctx, id, initiator, &idx);
    if (!st)
    {
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    if (st->reset)
    {
        maybe_cleanup_stream(ctx, idx);
        pthread_mutex_unlock(&ctx->mtx);
        return LIBP2P_MPLEX_ERR_RESET;
    }
    int init = st->initiator;
    pthread_mutex_unlock(&ctx->mtx);
    libp2p_mplex_err_t rc = libp2p_mplex_reset_stream(ctx->conn, id, init);
    if (rc && rc != LIBP2P_MPLEX_ERR_TIMEOUT)
        return rc;
    pthread_mutex_lock(&ctx->mtx);
    st = find_stream(ctx, id, initiator, &idx);
    if (st)
    {
        st->reset = 1;
        st->local_closed = 1;
        st->remote_closed = 1;
        maybe_cleanup_stream(ctx, idx);
    }
    pthread_mutex_unlock(&ctx->mtx);
    return rc;
}

/**
 * @brief Retrieve the next incoming stream accepted by the remote peer.
 *
 * @param ctx Mplex context.
 * @param out Receives the pointer to the accepted stream.
 * @return LIBP2P_MPLEX_OK on success, LIBP2P_MPLEX_ERR_AGAIN if none are pending.
 */
libp2p_mplex_err_t libp2p_mplex_accept_stream(libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t **out)
{
    if (!ctx || !out)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    libp2p_mplex_stream_t *st = libp2p_mplex_queue_pop(&ctx->incoming);
    if (!st)
        return LIBP2P_MPLEX_ERR_AGAIN;
    *out = st;
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Update local stream state based on an incoming frame.
 *
 * This function performs all protocol checks and may queue new streams for
 * acceptance. It is normally called from the processing loop.
 *
 * @param ctx Context to update.
 * @param fr  Frame that was received.
 */
libp2p_mplex_err_t libp2p_mplex_dispatch_frame(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_frame_t *fr)
{
    if (!ctx || !fr)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    if (fr->id >= MPLEX_MAX_STREAM_ID)
        return proto_violation(ctx);
    /*
     * Update local stream state based on the frame flag.  The mapping of flag
     * values to operations follows the mplex specification in
     * specs/mplex/README.md.
     */
    libp2p_mplex_err_t rc = LIBP2P_MPLEX_OK;
    int reset = 0;
    uint64_t reset_id = 0;
    int reset_init = 0;

    pthread_mutex_lock(&ctx->mtx);
    size_t idx = 0;
    libp2p_mplex_stream_t *st = NULL;
    switch (fr->flag)
    {
        case LIBP2P_MPLEX_NEW_STREAM:
            /* Remote side opened a new stream. Create local state for it. */
            st = find_stream(ctx, fr->id, 0, &idx);
            if (st)
            {
                rc = proto_violation(ctx);
                break;
            }
            st = calloc(1, sizeof(*st));
            if (!st)
            {
                rc = LIBP2P_MPLEX_ERR_INTERNAL;
                break;
            }
            st->id = fr->id;
            st->initiator = 0;
            if (fr->data_len)
            {
                st->name = malloc(fr->data_len);
                if (!st->name)
                {
                    free(st);
                    rc = LIBP2P_MPLEX_ERR_INTERNAL;
                    break;
                }
                memcpy(st->name, fr->data, fr->data_len);
                st->name_len = fr->data_len;
            }
            else
            {
                st->name = NULL;
                st->name_len = 0;
            }
            /* Track the new stream so it can be serviced later. */
            if (!mplex_stream_array_push(&ctx->streams, st))
            {
                free(st->name);
                free(st);
                pthread_mutex_unlock(&ctx->mtx);
                return LIBP2P_MPLEX_ERR_INTERNAL;
            }
            /* Make the new stream available to acceptor threads. */
            libp2p_mplex_queue_push(&ctx->incoming, st);
            break;
        case LIBP2P_MPLEX_CLOSE_INITIATOR:
            /* Remote closed its sending side (we are receiver). */
            if (fr->data_len)
            {
                rc = proto_violation(ctx);
                break;
            }
            st = find_stream(ctx, fr->id, 0, &idx);
            if (!st)
                st = find_stream(ctx, fr->id, 1, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }
            st->remote_closed = 1;
            maybe_cleanup_stream(ctx, idx);
            break;
        case LIBP2P_MPLEX_CLOSE_RECEIVER:
            /* Remote closed the receiving side (we are initiator). */
            if (fr->data_len)
            {
                rc = proto_violation(ctx);
                break;
            }
            st = find_stream(ctx, fr->id, 1, &idx);
            if (!st)
                st = find_stream(ctx, fr->id, 0, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }
            st->remote_closed = 1;
            maybe_cleanup_stream(ctx, idx);
            break;
        case LIBP2P_MPLEX_RESET_INITIATOR:
            /* Immediate reset from the remote initiator side. */
            if (fr->data_len)
            {
                rc = proto_violation(ctx);
                break;
            }
            st = find_stream(ctx, fr->id, 0, &idx);
            if (!st)
                st = find_stream(ctx, fr->id, 1, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }
            st->reset = 1;
            st->local_closed = 1;
            st->remote_closed = 1;
            free(st->buf);
            st->buf = NULL;
            st->buf_len = st->buf_pos = 0;
            break;
        case LIBP2P_MPLEX_RESET_RECEIVER:
            /* Immediate reset from the remote receiver side. */
            if (fr->data_len)
            {
                rc = proto_violation(ctx);
                break;
            }
            st = find_stream(ctx, fr->id, 1, &idx);
            if (!st)
                st = find_stream(ctx, fr->id, 0, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }
            st->reset = 1;
            st->local_closed = 1;
            st->remote_closed = 1;
            free(st->buf);
            st->buf = NULL;
            st->buf_len = st->buf_pos = 0;
            break;
        case LIBP2P_MPLEX_MSG_INITIATOR:
            /* Data from the stream initiator side. Append to buffer. */
            st = find_stream(ctx, fr->id, 0, &idx);
            if (!st)
                st = find_stream(ctx, fr->id, 1, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (st->remote_closed)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (fr->data_len)
            {
                /* Grow the receive buffer with any unread data preserved. */
                size_t unread = st->buf_len > st->buf_pos ? st->buf_len - st->buf_pos : 0;
                if (unread && st->buf_pos > 0)
                    memmove(st->buf, st->buf + st->buf_pos, unread);
                uint8_t *tmp = realloc(st->buf, unread + fr->data_len);
                if (!tmp)
                {
                    rc = LIBP2P_MPLEX_ERR_INTERNAL;
                    break;
                }
                memcpy(tmp + unread, fr->data, fr->data_len);
                st->buf = tmp;
                st->buf_len = unread + fr->data_len;
                st->buf_pos = 0;
                /* Avoid unbounded memory usage (see spec implementation notes). */
                if (st->buf_len > MPLEX_MAX_RECV_BUF)
                {
                    reset = 1;
                    reset_id = st->id;
                    reset_init = st->initiator;
                }
            }
            break;
        case LIBP2P_MPLEX_MSG_RECEIVER:
            /* Data from the receiving side. Append to buffer. */
            st = find_stream(ctx, fr->id, 1, &idx);
            if (!st)
                st = find_stream(ctx, fr->id, 0, &idx);
            if (!st)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (st->remote_closed)
            {
                rc = proto_violation(ctx);
                break;
            }
            if (fr->data_len)
            {
                size_t unread = st->buf_len > st->buf_pos ? st->buf_len - st->buf_pos : 0;
                if (unread && st->buf_pos > 0)
                    memmove(st->buf, st->buf + st->buf_pos, unread);
                uint8_t *tmp = realloc(st->buf, unread + fr->data_len);
                if (!tmp)
                {
                    rc = LIBP2P_MPLEX_ERR_INTERNAL;
                    break;
                }
                memcpy(tmp + unread, fr->data, fr->data_len);
                st->buf = tmp;
                st->buf_len = unread + fr->data_len;
                st->buf_pos = 0;
                /* Avoid unbounded memory usage (see spec implementation notes). */
                if (st->buf_len > MPLEX_MAX_RECV_BUF)
                {
                    reset = 1;
                    reset_id = st->id;
                    reset_init = st->initiator;
                }
            }
            break;
        default:
            /* Unknown flag => protocol violation. */
            rc = proto_violation(ctx);
            break;
    }
    pthread_mutex_unlock(&ctx->mtx);
    if (reset && rc == LIBP2P_MPLEX_OK)
        rc = libp2p_mplex_stream_reset(ctx, reset_id, reset_init);
    return rc;
}

/**
 * @brief Processing loop that runs until ::libp2p_mplex_stop is invoked.
 *
 * Frames are read from the connection and dispatched one by one.
 *
 * @param ctx Context to operate on.
 */
libp2p_mplex_err_t libp2p_mplex_process_loop(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    while (!atomic_load_explicit(&ctx->stop, memory_order_relaxed))
    {
        libp2p_mplex_err_t rc = libp2p_mplex_process_one(ctx);
        if (rc)
            return rc;
    }
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Perform a single iteration of the processing loop.
 *
 * Reads one frame from the connection and dispatches it.
 *
 * @param ctx Context to operate on.
 */
libp2p_mplex_err_t libp2p_mplex_process_one(libp2p_mplex_ctx_t *ctx)
{
    if (!ctx)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    libp2p_mplex_frame_t fr = {0};
    libp2p_mplex_err_t rc = libp2p_mplex_read_frame(ctx->conn, &fr);
    if (rc)
    {
        if (rc == LIBP2P_MPLEX_ERR_PROTO_MAL)
            rc = proto_violation(ctx);
        return rc;
    }
    rc = libp2p_mplex_dispatch_frame(ctx, &fr);
    if (rc == LIBP2P_MPLEX_ERR_PROTO_MAL)
        rc = proto_violation(ctx);
    libp2p_mplex_frame_free(&fr);
    return rc;
}

/**
 * @brief Signal the processing loop to exit at the next opportunity.
 *
 * @param ctx Context to stop.
 */
void libp2p_mplex_stop(libp2p_mplex_ctx_t *ctx)
{
    if (ctx)
        atomic_store_explicit(&ctx->stop, true, memory_order_relaxed);
}

int send_length_prefixed_message(libp2p_mplex_ctx_t *mx, uint64_t stream_id, const char *message, int initiator)
{
    if (!mx || !message)
        return -1;

    size_t msg_len = strlen(message);
    uint8_t varint_buf[10];
    size_t varint_len;
    if (unsigned_varint_encode(msg_len, varint_buf, sizeof(varint_buf), &varint_len) != UNSIGNED_VARINT_OK)
        return -1;

    if (libp2p_mplex_stream_send(mx, stream_id, initiator, varint_buf, varint_len) != LIBP2P_MPLEX_OK)
        return -1;

    if (libp2p_mplex_stream_send(mx, stream_id, initiator, (const uint8_t *)message, msg_len) != LIBP2P_MPLEX_OK)
        return -1;

    return 0;
}

int recv_length_prefixed_message(libp2p_mplex_ctx_t *mx, uint64_t stream_id, int initiator, char *buffer, size_t max_len)
{
    if (!mx || !buffer)
        return -1;
    uint8_t varint_buf[10];
    size_t bytes_read = 0;
    uint64_t msg_len = 0;
    size_t varint_bytes = 0;
    for (int i = 0; i < 10; i++)
    {
        libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(mx, stream_id, initiator, &varint_buf[varint_bytes], 1, &bytes_read);
        if (rc != LIBP2P_MPLEX_OK)
            return -1;
        if (bytes_read == 0)
        {
            if (libp2p_mplex_process_one(mx) != LIBP2P_MPLEX_OK)
                usleep(1000);
            else
                usleep(1000);
            i--; /* retry same byte */
            continue;
        }
        varint_bytes++;
        size_t consumed;
        if (unsigned_varint_decode(varint_buf, varint_bytes, &msg_len, &consumed) == UNSIGNED_VARINT_OK)
            break;
    }
    if (msg_len == 0 || msg_len >= max_len)
        return -1;
    size_t total = 0;
    while (total < msg_len)
    {
        size_t got = 0;
        libp2p_mplex_err_t rc = libp2p_mplex_stream_recv(mx, stream_id, initiator, (uint8_t *)buffer + total, msg_len - total, &got);
        if (rc != LIBP2P_MPLEX_OK)
            return -1;
        if (got == 0)
        {
            if (libp2p_mplex_process_one(mx) != LIBP2P_MPLEX_OK)
                usleep(1000);
            else
                usleep(1000);
            continue;
        }
        total += got;
    }
    buffer[msg_len] = '\0';
    return (int)msg_len;
}