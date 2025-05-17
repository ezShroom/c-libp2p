#ifndef CONNECTION_H
#define CONNECTION_H

/**
 * @file connection.h
 * @brief Opaque raw-connection handle for C-libp2p.
 *
 * A **connection** is a bidirectional byte pipe supplied by a transport
 * (TCP socket, QUIC stream, …) *before* any security or multiplexing is
 * applied.  Higher layers treat it like a POSIX socket with a little
 * extra metadata.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "multiformats/multiaddr/multiaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Forward declarations                                                      */
/* ------------------------------------------------------------------------- */

struct libp2p_connection;  
typedef struct libp2p_connection libp2p_conn_t;

/* ------------------------------------------------------------------------- */
/* Error codes                                                               */
/* ------------------------------------------------------------------------- */

/**
 * @enum libp2p_conn_err_t
 * @brief Return codes for connection operations.
 *
 * Positive values are valid byte counts; non-zero negatives are errors.
 */
typedef enum
{
    LIBP2P_CONN_OK = 0,               /**< No error (unused—success is byte count). */
    LIBP2P_CONN_ERR_NULL_PTR = -1,    /**< Required pointer was NULL.               */
    LIBP2P_CONN_ERR_AGAIN = -2,       /**< Would block (EAGAIN / EWOULDBLOCK).      */
    LIBP2P_CONN_ERR_EOF = -3,         /**< Remote closed the connection.            */
    LIBP2P_CONN_ERR_CLOSED = -4,      /**< Operation after libp2p_conn_close().     */
    LIBP2P_CONN_ERR_TIMEOUT = -5,     /**< Deadline expired.                        */
    LIBP2P_CONN_ERR_INTERNAL = -6     /**< Unspecified internal failure.            */
} libp2p_conn_err_t;

/* ------------------------------------------------------------------------- */
/* Virtual table                                                             */
/* ------------------------------------------------------------------------- */

typedef struct
{
    /* I/O ----------------------------------------------------------------- */

    /**
     * @brief Read up to @p len bytes into @p buf.
     *
     * @return Positive byte count, or a negative libp2p_conn_err_t.
     */
    ssize_t (*read)(libp2p_conn_t *self, void *buf, size_t len);

    /**
     * @brief Write up to @p len bytes from @p buf.
     *
     * @return Positive byte count, or a negative libp2p_conn_err_t.
     */
    ssize_t (*write)(libp2p_conn_t *self, const void *buf, size_t len);

    /**
     * @brief Set a combined read/write deadline in milliseconds from now.
     *        Pass 0 to clear any existing deadline.
     */
    libp2p_conn_err_t (*set_deadline)(libp2p_conn_t *self, uint64_t ms);

    /* Metadata ------------------------------------------------------------ */

    const multiaddr_t *(*local_addr)(libp2p_conn_t *self);
    const multiaddr_t *(*remote_addr)(libp2p_conn_t *self);

    /* Lifecycle ----------------------------------------------------------- */

    libp2p_conn_err_t (*close)(libp2p_conn_t *self);
    void (*free)(libp2p_conn_t *self);

} libp2p_conn_vtbl_t;

/* ------------------------------------------------------------------------- */
/* Public struct                                                             */
/* ------------------------------------------------------------------------- */

struct libp2p_connection
{
    const libp2p_conn_vtbl_t *vt;
    void                     *ctx;  /**< Transport-specific state. */
};

/* ------------------------------------------------------------------------- */
/* Convenience inline wrappers                                               */
/* ------------------------------------------------------------------------- */

static inline ssize_t
libp2p_conn_read(libp2p_conn_t *c, void *buf, size_t len)
{
    return c && c->vt ? c->vt->read(c, buf, len) : LIBP2P_CONN_ERR_NULL_PTR;
}

static inline ssize_t
libp2p_conn_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    return c && c->vt ? c->vt->write(c, buf, len) : LIBP2P_CONN_ERR_NULL_PTR;
}

static inline libp2p_conn_err_t
libp2p_conn_set_deadline(libp2p_conn_t *c, uint64_t ms)
{
    return c && c->vt ? c->vt->set_deadline(c, ms) : LIBP2P_CONN_ERR_NULL_PTR;
}

static inline const multiaddr_t *
libp2p_conn_local_addr(libp2p_conn_t *c)
{
    return c && c->vt ? c->vt->local_addr(c) : NULL;
}

static inline const multiaddr_t *
libp2p_conn_remote_addr(libp2p_conn_t *c)
{
    return c && c->vt ? c->vt->remote_addr(c) : NULL;
}

static inline libp2p_conn_err_t
libp2p_conn_close(libp2p_conn_t *c)
{
    return c && c->vt ? c->vt->close(c) : LIBP2P_CONN_ERR_NULL_PTR;
}

static inline void
libp2p_conn_free(libp2p_conn_t *c)
{
    if (c && c->vt && c->vt->free) c->vt->free(c);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CONNECTION_H */