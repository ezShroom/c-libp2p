#include "protocol/mplex/protocol_mplex_queue.h"
#include "protocol/mplex/protocol_mplex.h"
#include <stdlib.h>

/**
 * @brief Initialize an empty stream queue.
 *
 * Sets up mutexes and condition variables so that streams can be safely
 * enqueued and dequeued from multiple threads.
 *
 * @param q Queue to initialize.
 */
void libp2p_mplex_queue_init(mplex_stream_queue_t *q)
{
    pthread_mutex_init(&q->mtx, NULL);
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#if defined(_POSIX_MONOTONIC_CLOCK) && !defined(__APPLE__)
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&q->cond, &attr);
    pthread_condattr_destroy(&attr);
    q->head = q->tail = NULL;
    atomic_init(&q->len, 0);
}

/**
 * @brief Push a stream pointer onto the tail of the queue.
 *
 * Ownership of the stream pointer is transferred to the queue.
 *
 * @param q Queue to modify.
 * @param s Stream to enqueue.
 */
void libp2p_mplex_queue_push(mplex_stream_queue_t *q, struct libp2p_mplex_stream *s)
{
    mplex_stream_node_t *n = malloc(sizeof(*n));
    if (!n)
        return;
    n->s = s;
    n->next = NULL;
    pthread_mutex_lock(&q->mtx);
    if (q->tail)
    {
        q->tail->next = n;
        q->tail = n;
    }
    else
    {
        q->head = q->tail = n;
    }
    atomic_fetch_add_explicit(&q->len, 1, memory_order_relaxed);
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mtx);
}

/**
 * @brief Remove and return the stream at the head of the queue.
 *
 * @param q Queue to pop from.
 * @return Pointer to the popped stream, or NULL if the queue is empty.
 */
struct libp2p_mplex_stream *libp2p_mplex_queue_pop(mplex_stream_queue_t *q)
{
    pthread_mutex_lock(&q->mtx);
    mplex_stream_node_t *n = q->head;
    if (!n)
    {
        pthread_mutex_unlock(&q->mtx);
        return NULL;
    }
    q->head = n->next;
    if (!q->head)
        q->tail = NULL;
    atomic_fetch_sub_explicit(&q->len, 1, memory_order_relaxed);
    pthread_mutex_unlock(&q->mtx);
    struct libp2p_mplex_stream *s = n->s;
    free(n);
    return s;
}

/**
 * @brief Obtain the current number of elements in the queue.
 *
 * @param q Queue to inspect.
 * @return The number of streams currently enqueued.
 */
size_t libp2p_mplex_queue_length(mplex_stream_queue_t *q) { return atomic_load_explicit(&q->len, memory_order_relaxed); }
