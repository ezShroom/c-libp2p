#include "multiformats/unsigned_varint/unsigned_varint.h"
#include <string.h>

/**
 * @brief Calculate the number of bytes required to encode a 64-bit unsigned integer as a varint.
 *
 * @param value The 64-bit unsigned integer to be encoded.
 * @return The number of bytes required to encode the value.
 */
static size_t varint_size_64(uint64_t value)
{
    size_t size = 0;
    do
    {
        size++;
        value >>= 7;
    } while (value != 0);
    return size;
}

/**
 * @brief Encode a 64-bit unsigned integer into a varint format.
 *
 * @param value The 64-bit unsigned integer to encode.
 * @param out The buffer to write the encoded varint to.
 * @param out_size The size of the output buffer.
 * @param written Pointer to store the number of bytes written to the output buffer.
 * @return mf_varint_err_t Error code indicating success or type of failure.
 */
mf_varint_err_t mf_uvarint_encode(uint64_t value, uint8_t *out, size_t out_size, size_t *written)
{
    if (!out || !written)
    {
        return MF_VARINT_ERR_BUFFER_OVER;
    }

    if (value > 0x7FFFFFFFFFFFFFFFULL)
    {
        return MF_VARINT_ERR_VALUE_OVERFLOW;
    }

    size_t needed = varint_size_64(value);
    if (needed > 9)
    {
        return MF_VARINT_ERR_VALUE_OVERFLOW;
    }

    if (needed > out_size)
    {
        return MF_VARINT_ERR_BUFFER_OVER;
    }

    *written = 0;
    while (value >= 0x80)
    {
        out[(*written)++] = (uint8_t)((value & 0x7F) | 0x80);
        value >>= 7;
    }
    out[(*written)++] = (uint8_t)(value & 0x7F);

    return MF_VARINT_OK;
}

/**
 * @brief Decode a varint-encoded 64-bit unsigned integer.
 *
 * @param in The input buffer containing the varint-encoded data.
 * @param in_size The size of the input buffer.
 * @param value Pointer to store the decoded 64-bit unsigned integer.
 * @param read Pointer to store the number of bytes read from the input buffer.
 * @return mf_varint_err_t Error code indicating success or type of failure.
 */
mf_varint_err_t mf_uvarint_decode(const uint8_t *in, size_t in_size, uint64_t *value, size_t *read)
{
    if (!in || !value || !read)
    {
        return MF_VARINT_ERR_BUFFER_OVER;
    }

    if (in_size == 0)
    {
        return MF_VARINT_ERR_TOO_LONG;
    }

    uint64_t result = 0;
    size_t shift = 0;
    size_t idx = 0;

    for (; idx < in_size; idx++)
    {
        uint8_t byte = in[idx];
        uint64_t lower7 = (uint64_t)(byte & 0x7F);

        if (shift > 63)
        {
            return MF_VARINT_ERR_VALUE_OVERFLOW;
        }

        result |= (lower7 << shift);

        if ((byte & 0x80) == 0)
        {
            idx++;
            break;
        }
        shift += 7;
    }

    if (idx == in_size)
    {
        if ((in[idx - 1] & 0x80) != 0)
        {
            return MF_VARINT_ERR_TOO_LONG;
        }
    }

    if (result > 0x7FFFFFFFFFFFFFFFULL)
    {
        return MF_VARINT_ERR_VALUE_OVERFLOW;
    }

    if (idx > 9)
    {
        return MF_VARINT_ERR_TOO_LONG;
    }

    uint8_t reencoded[10];
    size_t reencoded_size = 0;
    mf_varint_err_t enc_err =
        mf_uvarint_encode(result, reencoded, sizeof(reencoded), &reencoded_size);
    if (enc_err != MF_VARINT_OK)
    {
        return enc_err;
    }

    if (reencoded_size != idx || memcmp(reencoded, in, idx) != 0)
    {
        return MF_VARINT_ERR_NOT_MINIMAL;
    }

    *value = result;
    *read = idx;
    return MF_VARINT_OK;
}

/**
 * @brief Calculate the number of bytes required to encode a 64-bit unsigned integer as a varint.
 *
 * @param value The 64-bit unsigned integer to be encoded.
 * @return The number of bytes required to encode the value.
 */
size_t mf_uvarint_size(uint64_t value)
{
    return varint_size_64(value);
}