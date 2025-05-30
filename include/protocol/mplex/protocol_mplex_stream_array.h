#ifndef PROTOCOL_MPLEX_STREAM_ARRAY_H
#define PROTOCOL_MPLEX_STREAM_ARRAY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libp2p_mplex_stream;

/**
 * Dynamic array of mplex streams.
 */
typedef struct
{
    struct libp2p_mplex_stream **items; /**< Pointer to array items. */
    size_t len;                    /**< Number of used entries. */
    size_t cap;                    /**< Allocated capacity.     */
} mplex_stream_array_t;

void mplex_stream_array_init(mplex_stream_array_t *arr);
void mplex_stream_array_free(mplex_stream_array_t *arr);
int  mplex_stream_array_push(mplex_stream_array_t *arr, struct libp2p_mplex_stream *s);
struct libp2p_mplex_stream *mplex_stream_array_remove(mplex_stream_array_t *arr, size_t idx);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_MPLEX_STREAM_ARRAY_H */
