#ifndef PROTOCOL_MPLEX_QUEUE_H
#define PROTOCOL_MPLEX_QUEUE_H

#include <pthread.h>
#include <stdatomic.h>

#include <stdint.h>

/**
 * @file protocol_mplex_queue.h
 * @brief Thread-safe queue for mplex stream handles.
 */

struct libp2p_mplex_stream;

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Node in the stream queue.
 */
typedef struct mplex_stream_node
{
    struct libp2p_mplex_stream *s;  /**< Stored stream. */
    struct mplex_stream_node *next; /**< Next node.     */
} mplex_stream_node_t;

/**
 * @brief FIFO queue of streams.
 */
typedef struct
{
    mplex_stream_node_t *head; /**< Front of the queue.  */
    mplex_stream_node_t *tail; /**< Back of the queue.   */
    pthread_mutex_t mtx;       /**< Mutex protecting q.  */
    pthread_cond_t cond;       /**< Signaled on new item.*/
    atomic_size_t len;         /**< Number of elements.  */
} mplex_stream_queue_t;

/**
 * @brief Initializes a stream queue.
 *
 * @param q Pointer to the queue to initialize.
 */
void libp2p_mplex_queue_init(mplex_stream_queue_t *q);

/**
 * @brief Enqueues a stream.
 *
 * @param q Pointer to the queue to enqueue onto.
 * @param s The stream to enqueue.
 */
void libp2p_mplex_queue_push(mplex_stream_queue_t *q, struct libp2p_mplex_stream *s);

/**
 * @brief Dequeues a stream, blocking if the queue is empty.
 *
 * @param q Pointer to the queue to dequeue from.
 * @return The dequeued stream.
 */
struct libp2p_mplex_stream *libp2p_mplex_queue_pop(mplex_stream_queue_t *q);

/**
 * @brief Returns the current length of the queue.
 *
 * @param q Pointer to the queue to query.
 * @return The length of the queue.
 */
size_t libp2p_mplex_queue_length(mplex_stream_queue_t *q);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_MPLEX_QUEUE_H */
