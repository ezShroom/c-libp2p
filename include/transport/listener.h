#ifndef LISTENER_H
#define LISTENER_H

/**
 * @file listener.h
 * @brief Passive listen/accept handle for C-libp2p.
 *
 * A **listener** accepts inbound raw connections produced by a transport
 * (e.g. TCP `accept()` loop).  Its lifecycle is independent from the
 * transport object so you can listen on multiple addresses with one
 * transport instance.
 */

#include <pthread.h> /* for listener mutex */
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "transport/connection.h" /* for libp2p_conn_t */

#ifdef __cplusplus
extern "C"
{
#endif

/* ------------------------------------------------------------------------- */
/* Forward declarations                                                      */
/* ------------------------------------------------------------------------- */

struct libp2p_listener;
typedef struct libp2p_listener libp2p_listener_t;

/* ------------------------------------------------------------------------- */
/* Error codes                                                               */
/* ------------------------------------------------------------------------- */

/**
 * @enum libp2p_listener_err_t
 * @brief Return codes for listener operations.
 */
typedef enum
{
    LIBP2P_LISTENER_OK = 0,
    LIBP2P_LISTENER_ERR_NULL_PTR = -1,
    LIBP2P_LISTENER_ERR_AGAIN = -2, /**< Would block / no pending conns. */
    LIBP2P_LISTENER_ERR_CLOSED = -3,
    LIBP2P_LISTENER_ERR_INTERNAL = -4,
    LIBP2P_LISTENER_ERR_TIMEOUT = -5,
    LIBP2P_LISTENER_ERR_BACKOFF = -6, /**< Listener is temporarily disabled due to backoff. */
    LIBP2P_LISTENER_ERR_MUTEX = -7,
    LIBP2P_LISTENER_ERR_OVERFLOW = -8 /**< Refcount overflow: close this listener and create a new one; retrying will always fail. */
} libp2p_listener_err_t;

/* ------------------------------------------------------------------------- */
/* Virtual table                                                             */
/* ------------------------------------------------------------------------- */

typedef struct
{
    /**
     * @brief Accept the next inbound connection.
     *
     * For non-blocking transports, return LIBP2P_LISTENER_ERR_AGAIN when
     * there is nothing to accept right now.
     */
    libp2p_listener_err_t (*accept)(libp2p_listener_t *self, libp2p_conn_t **out_conn);

    libp2p_listener_err_t (*local_addr)(libp2p_listener_t *self, multiaddr_t **out);

    /* Lifecycle ----------------------------------------------------------- */

    libp2p_listener_err_t (*close)(libp2p_listener_t *self);
    void (*free)(libp2p_listener_t *self);

} libp2p_listener_vtbl_t;

/* ------------------------------------------------------------------------- */
/* Public struct                                                             */
/* ------------------------------------------------------------------------- */

struct libp2p_listener
{
    const libp2p_listener_vtbl_t *vt;
    _Atomic(void *) ctx;          /**< Transport-specific state (atomic pointer for thread‑safe access) */
    _Atomic unsigned int refcount; /**< Reference count for thread-safe lifetime */
    pthread_mutex_t mutex;         /**< Mutex to serialize vtbl calls */
};

/**
 * @brief Increment the listener reference count.
 */
static inline void libp2p_listener_ref(libp2p_listener_t *l)
{
    if (!l)
    {
        return;
    }
    atomic_fetch_add(&l->refcount, 1);
}

/**
 * @brief Decrement the listener reference count and free when zero.
 */
static inline void libp2p_listener_unref(libp2p_listener_t *l)
{
    if (!l)
    {
        return;
    }
    if (atomic_fetch_sub(&l->refcount, 1) == 1)
    {
        if (l->vt && l->vt->free)
        {
            l->vt->free(l);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Convenience inline wrappers                                               */
/* ------------------------------------------------------------------------- */
static inline libp2p_listener_err_t libp2p_listener_accept(libp2p_listener_t *l, libp2p_conn_t **out)
{
    if (!l || !out)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    libp2p_listener_ref(l); 

    pthread_mutex_lock(&l->mutex);
    // Ensure vt is valid after potentially waiting for the lock
    // and after incrementing refcount (though ref should protect it)
    libp2p_listener_err_t ret = LIBP2P_LISTENER_ERR_INTERNAL; // Default error
    if (l->vt && l->vt->accept)
    {
        ret = l->vt->accept(l, out);
    }
    pthread_mutex_unlock(&l->mutex);

    libp2p_listener_unref(l); 
    return ret;
}

static inline libp2p_listener_err_t libp2p_listener_local_addr(libp2p_listener_t *l, multiaddr_t **out)
{
    if (!l || !out)
    { 
        return LIBP2P_LISTENER_ERR_NULL_PTR;
    }

    libp2p_listener_ref(l); 

    pthread_mutex_lock(&l->mutex);
    libp2p_listener_err_t ret = LIBP2P_LISTENER_ERR_NULL_PTR; // Default error if vt or func is null
    if (l->vt && l->vt->local_addr)
    { // Check vt and specific function pointer
        ret = l->vt->local_addr(l, out);
    }
    pthread_mutex_unlock(&l->mutex);

    libp2p_listener_unref(l); 
    return ret;
}

static inline libp2p_listener_err_t libp2p_listener_close(libp2p_listener_t *l)
{
    if (!l)
    {
        return LIBP2P_LISTENER_ERR_NULL_PTR; // l->vt check after ref
    }

    libp2p_listener_ref(l); 

    pthread_mutex_lock(&l->mutex);
    libp2p_listener_err_t ret = LIBP2P_LISTENER_ERR_NULL_PTR; // Default error
    if (l->vt && l->vt->close)
    { // Check vt and specific function pointer
        ret = l->vt->close(l);
    }
    pthread_mutex_unlock(&l->mutex);

    libp2p_listener_unref(l); 
    return ret;
}

static inline void libp2p_listener_free(libp2p_listener_t *l) 
{ 
    if (!l)
    {
        return;
    }
    
    libp2p_listener_unref(l); 
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LISTENER_H */