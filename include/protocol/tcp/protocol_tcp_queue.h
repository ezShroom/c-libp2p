#ifndef PROTOCOL_TCP_QUEUE_H
#define PROTOCOL_TCP_QUEUE_H
/*
 *  protocol_tcp_queue.h ― minimal MPSC queue for accepted connections
 *
 *  The implementation is in protocol_tcp_queue.c.
 *
 *  Thread model:
 *      • any thread may push (typically the poll-loop)  
 *      • one thread (the listener’s accept()) pops
 */

#include <pthread.h>
#include <stdatomic.h>
#include "transport/connection.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/*  Node & queue types                                                       */
/* ------------------------------------------------------------------------- */
typedef struct conn_node
{
    libp2p_conn_t       *c;
    struct conn_node    *next;
} conn_node_t;

typedef struct
{
    conn_node_t        *head;
    conn_node_t        *tail;
    pthread_mutex_t     mtx;
    pthread_cond_t      cond;
    atomic_size_t       len;
} conn_queue_t;

/* ------------------------------------------------------------------------- */
/*  API                                                                      */
/* ------------------------------------------------------------------------- */
void           cq_init(conn_queue_t *q);
void           cq_push(conn_queue_t *q, libp2p_conn_t *c);
/* Returns NULL if the queue is empty */
libp2p_conn_t *cq_pop (conn_queue_t *q);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_TCP_QUEUE_H */
