#include "protocol/mplex/protocol_mplex_stream_array.h"
#include "protocol/mplex/protocol_mplex.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Initialize a mplex stream array structure.
 *
 * Sets up an empty array that can hold pointers to mplex streams.
 *
 * @param arr Pointer to the array structure to initialize.
 */
void mplex_stream_array_init(mplex_stream_array_t *arr)
{
    if (!arr)
        return;
    arr->items = NULL;
    arr->len = 0;
    arr->cap = 0;
}

/**
 * @brief Release all resources held by a mplex stream array.
 *
 * Frees the internal storage and resets the array fields to zero.
 *
 * @param arr Array to clean up.
 */
void mplex_stream_array_free(mplex_stream_array_t *arr)
{
    if (!arr)
        return;
    free(arr->items);
    arr->items = NULL;
    arr->len = 0;
    arr->cap = 0;
}

/**
 * @brief Append a stream pointer to the array, growing it if required.
 *
 * @param arr Array to modify.
 * @param s   Stream to append.
 * @return 1 on success, 0 on allocation failure or if @a arr is NULL.
 */
int mplex_stream_array_push(mplex_stream_array_t *arr, struct libp2p_mplex_stream *s)
{
    if (!arr)
        return 0;
    if (arr->len >= arr->cap)
    {
        size_t new_cap = arr->cap ? arr->cap * 2 : 4;
        void *tmp = realloc(arr->items, new_cap * sizeof(*arr->items));
        if (!tmp)
            return 0;
        arr->items = tmp;
        arr->cap = new_cap;
    }
    arr->items[arr->len++] = s;
    return 1;
}

/**
 * @brief Remove a stream from the array by index.
 *
 * The caller becomes responsible for freeing the returned stream pointer.
 *
 * @param arr Array to modify.
 * @param idx Index of the element to remove.
 * @return Pointer to the removed stream or NULL on error.
 */
struct libp2p_mplex_stream *mplex_stream_array_remove(mplex_stream_array_t *arr, size_t idx)
{
    if (!arr || idx >= arr->len)
        return NULL;
    struct libp2p_mplex_stream *s = arr->items[idx];
    for (size_t i = idx + 1; i < arr->len; ++i)
        arr->items[i - 1] = arr->items[i];
    arr->len--;
    return s;
}
