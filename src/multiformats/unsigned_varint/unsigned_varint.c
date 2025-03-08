#include <string.h>  /* for size_t, memset, etc. */
#include "multiformats/unsigned_varint/unsigned_varint.h"

/* 
 * Internal function to compute the size of a varint without a loop 
 * - used by mf_uvarint_size().
 * 
 * We do a quick approach: 
 * - If value < (1 << 7), need 1 byte
 * - If value < (1 << 14), need 2 bytes
 * - ...
 * - Up to 63 bits: if value < (1ULL << 63), need 9 bytes
 *   (But note that 2^63 - 1 also fits in 9 bytes.)
 *
 * This function never returns 0 because the smallest size is 1.
 */
static size_t varint_size_64(uint64_t value)
{
    size_t size = 0;
    do {
        size++;
        value >>= 7;
    } while (value != 0);
    return size;
}

mf_varint_err_t mf_uvarint_encode(uint64_t value, 
                                  uint8_t *out, 
                                  size_t out_size, 
                                  size_t *written)
{
    /* Minimum buffer for any 63-bit number is up to 9 bytes */
    if (!out || !written) {
        return MF_VARINT_ERR_BUFFER_OVER;
    }

    /* We compute how many bytes we actually need */
    size_t needed = varint_size_64(value);
    if (needed > out_size) {
        return MF_VARINT_ERR_BUFFER_OVER;
    }

    *written = 0;
    while (value >= 0x80) {
        out[(*written)++] = (uint8_t)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    /* Final byte */
    out[(*written)++] = (uint8_t)(value & 0x7F);

    return MF_VARINT_OK;
}

mf_varint_err_t mf_uvarint_decode(const uint8_t *in, 
                                  size_t in_size, 
                                  uint64_t *value, 
                                  size_t *read)
{
    if (!in || !value || !read) {
        return MF_VARINT_ERR_BUFFER_OVER; /* Generic “bad usage” error. */
    }

    uint64_t result = 0;
    size_t shift = 0;
    size_t idx = 0;

    for (; idx < in_size; idx++) {
        uint8_t byte = in[idx];
        /* bits 6..0 */
        uint64_t lower7 = (uint64_t)(byte & 0x7F);

        /* Check for overflow (if shifting 7 bits would go beyond 64 bits).
           But we only allow up to 63 bits in practice, so check shift >= 63. */
        if (shift > 63) {
            return MF_VARINT_ERR_VALUE_OVERFLOW;
        }

        /* Add the bits to the result */
        result |= (lower7 << shift);

        if ((byte & 0x80) == 0) {
            /* This was the last byte. */
            idx++;
            break;
        } else {
            shift += 7;
        }
    }

    /* If we exit the loop without encountering a byte with MSB=0, 
       we didn't finish decoding. For a truncated buffer, we can either 
       fail or treat it as an error. */
    if (idx == in_size && (in[idx - 1] & 0x80) != 0) {
        /* We ran out of bytes but still haven't finished decoding. */
        return MF_VARINT_ERR_TOO_LONG; 
    }

    /* If we used more than 9 bytes, fail (spec: practical max). */
    if (idx > 9) {
        return MF_VARINT_ERR_TOO_LONG;
    }

    /* 
     * Now we must check minimal encoding:
     * We'll quickly re-encode the result and see if we used the same number of bytes.
     * This is a direct way to ensure minimality. 
     */
    uint8_t reencoded[10];
    size_t reencoded_size = 0;
    mf_uvarint_encode(result, reencoded, sizeof(reencoded), &reencoded_size);

    if (reencoded_size != idx ||
        (memcmp(reencoded, in, idx) != 0)) {
        /* Not minimal */
        return MF_VARINT_ERR_NOT_MINIMAL;
    }

    /* Store final results */
    *value = result;
    *read = idx;

    return MF_VARINT_OK;
}

size_t mf_uvarint_size(uint64_t value)
{
    return varint_size_64(value);
}