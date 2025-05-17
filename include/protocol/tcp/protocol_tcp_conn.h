#ifndef PROTOCOL_TCP_CONN_H
#define PROTOCOL_TCP_CONN_H
/*
 *  protocol_tcp_conn.h ― public-ish interface for a single TCP connection
 *
 *  By popular demand this header now publishes the full context
 *  struct plus all helper functions and the vtable.  Nothing here
 *  performs any I/O; the implementation lives in protocol/tcp/tcp_conn.c.
 *
 *  NOTE: These symbols are *primarily* intended for libp2p’s own
 *  transports / tests.  Treat the layout as semi-stable rather than a
 *  strict ABI commitment.
 */

#include <stddef.h>        /* size_t                  */
#include <stdint.h>        /* uint64_t                */
#include <stdatomic.h>     /* atomic_bool             */

#include "transport/connection.h"          /* libp2p_conn_t / vtbl / err enum   */
#include "multiformats/multiaddr/multiaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/*  Context structure                                                        */
/* ------------------------------------------------------------------------- */
/*  Exposed so that callers can, e.g., fetch the raw fd or the cached        */
/*  multiaddrs without doing another getsockname() / getpeername().          */
typedef struct tcp_conn_ctx {
    int              fd;           /* non-blocking, close-on-exec socket  */
    multiaddr_t     *local;        /* cached local multiaddr              */
    multiaddr_t     *remote;       /* cached peer multiaddr (nullable)    */
    atomic_bool      closed;       /* fast-path closed check              */
    uint64_t         deadline_at;  /* 0 = none; monotonic ms              */
} tcp_conn_ctx_t;

/* ------------------------------------------------------------------------- */
/*  I/O helpers (implemented in tcp_conn.c)                                  */
/* ------------------------------------------------------------------------- */
ssize_t tcp_conn_read (libp2p_conn_t *c, void *buf, size_t len);
ssize_t tcp_conn_write(libp2p_conn_t *c, const void *buf, size_t len);
libp2p_conn_err_t tcp_conn_set_deadline(libp2p_conn_t *c, uint64_t ms);

const multiaddr_t *tcp_conn_local (libp2p_conn_t *c);
const multiaddr_t *tcp_conn_remote(libp2p_conn_t *c);

libp2p_conn_err_t tcp_conn_close(libp2p_conn_t *c);
void              tcp_conn_free (libp2p_conn_t *c);

/* ------------------------------------------------------------------------- */
/*  Pre-wired vtable                                                         */
/* ------------------------------------------------------------------------- */
/*  tcp_conn.c defines the storage; we just forward-declare it here.         */
extern const libp2p_conn_vtbl_t TCP_CONN_VTBL;

/* ------------------------------------------------------------------------- */
/*  Constructor                                                              */
/* ------------------------------------------------------------------------- */
/**
 * Wrap an existing, already-connected (or connecting) TCP socket
 * descriptor into a libp2p connection object.
 *
 * The FD **must** be:
 *   • valid (≥ 0)  
 *   • non-blocking  
 *   • FD_CLOEXEC set (if platform supports it)
 *
 * On success, ownership of the FD transfers to the returned object and
 * will be closed via `tcp_conn_free()`.  Returns NULL on allocation
 * failure or if address conversion fails.
 */
libp2p_conn_t *make_tcp_conn(int fd);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_TCP_CONN_H */
