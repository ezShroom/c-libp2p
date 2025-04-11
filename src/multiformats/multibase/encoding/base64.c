#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "multiformats/multibase/multibase.h"

/* The base64 alphabet (RFC 4648, Table 1) */
static const char base64_alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Helper function to map a Base64 character to its 6-bit value.
 * Returns the corresponding value (0–63) or -1 if the character is invalid.
 */
static inline int base64_char_to_val(char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z')
    {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9')
    {
        return c - '0' + 52;
    }
    if (c == '+')
    {
        return 62;
    }
    if (c == '/')
    {
        return 63;
    }
    return -1;
}

/**
 * @brief Encode data into Base64 format (unpadded).
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base64 string.
 * @param out_len The size of the output buffer.
 * @return The number of Base64 characters written (excluding the null
 * terminator), or an error code indicating a null pointer, integer overflow,
 * or insufficient buffer size.
 */
int multibase_base64_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    size_t full_blocks = data_len / 3;
    size_t rem = data_len % 3;

    if (full_blocks > SIZE_MAX / 4 || (full_blocks == SIZE_MAX / 4 && rem > 0))
    {
        return MULTIBASE_ERR_OVERFLOW;
    }

    size_t encoded_len = full_blocks * 4;
    if (rem == 1)
    {
        encoded_len += 2;
    }
    else if (rem == 2)
    {
        encoded_len += 3;
    }

    if (out_len < encoded_len + 1)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    size_t i = 0;
    size_t j = 0;
    while (i + 3 <= data_len)
    {
        uint32_t triple = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | ((uint32_t)data[i + 2]);
        out[j++] = base64_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 6) & 0x3F];
        out[j++] = base64_alphabet[triple & 0x3F];
        i += 3;
    }
    if (rem == 1)
    {
        uint32_t triple = ((uint32_t)data[i]) << 16;
        out[j++] = base64_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 12) & 0x3F];
    }
    else if (rem == 2)
    {
        uint32_t triple = (((uint32_t)data[i]) << 16) | (((uint32_t)data[i + 1]) << 8);
        out[j++] = base64_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64_alphabet[(triple >> 6) & 0x3F];
    }
    out[j] = '\0';
    return (int)encoded_len;
}

/**
 * @brief Decode data from Base64 format (unpadded).
 *
 * @param in The input Base64 encoded string.
 * @param in_len The length of the input data.
 * @param out The buffer to store the decoded data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code
 *         indicating a null pointer, invalid input length, integer overflow,
 *         invalid character, or insufficient buffer size.
 */
int multibase_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    if (in_len == 0)
    {
        return 0;
    }
    size_t full_blocks = in_len / 4;
    size_t rem = in_len % 4;

    if (rem == 1)
    {
        return MULTIBASE_ERR_INVALID_INPUT_LEN;
    }

    if (full_blocks > SIZE_MAX / 3)
    {
        return MULTIBASE_ERR_OVERFLOW;
    }

    size_t decoded_len = full_blocks * 3;
    if (rem == 2)
    {
        if (decoded_len > SIZE_MAX - 1)
        {
            return MULTIBASE_ERR_OVERFLOW;
        }
        decoded_len += 1;
    }
    else if (rem == 3)
    {
        if (decoded_len > SIZE_MAX - 2)
        {
            return MULTIBASE_ERR_OVERFLOW;
        }
        decoded_len += 2;
    }
    if (out_len < decoded_len)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    size_t i = 0;
    size_t j = 0;
    for (size_t b = 0; b < full_blocks; b++)
    {
        uint32_t triple = 0;
        for (int k = 0; k < 4; k++)
        {
            char c = in[i++];
            int v = base64_char_to_val(c);
            if (v == -1)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            triple = (triple << 6) | v;
        }
        out[j++] = (triple >> 16) & 0xFF;
        out[j++] = (triple >> 8) & 0xFF;
        out[j++] = triple & 0xFF;
    }

    if (rem == 2)
    {
        uint32_t triple = 0;
        for (int k = 0; k < 2; k++)
        {
            char c = in[i++];
            int v = base64_char_to_val(c);
            if (v == -1)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            triple = (triple << 6) | v;
        }
        triple <<= 12;
        out[j++] = (triple >> 16) & 0xFF;
    }
    else if (rem == 3)
    {
        uint32_t triple = 0;
        for (int k = 0; k < 3; k++)
        {
            char c = in[i++];
            int v = base64_char_to_val(c);
            if (v == -1)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            triple = (triple << 6) | v;
        }
        triple <<= 6;
        out[j++] = (triple >> 16) & 0xFF;
        out[j++] = (triple >> 8) & 0xFF;
    }
    return (int)decoded_len;
}