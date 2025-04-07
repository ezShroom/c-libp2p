#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multibase/multibase.h"

/* The base64 URL alphabet (RFC 4648, Table 2) */
static const char base64url_alphabet[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * @brief Encode data into Base64 URL format (no padding) using the URL and
 * filename safe alphabet.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base64 URL string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written (excluding the null terminator), or
 * an error code indicating a null pointer or insufficient buffer size.
 */
int multibase_base64_url_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    size_t full_groups = data_len / 3;
    size_t remainder = data_len % 3;
    size_t encoded_len = full_groups * 4;

    if (remainder == 1)
    {
        encoded_len += 2;
    }
    else if (remainder == 2)
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
        uint32_t triple =
            ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | (uint32_t)data[i + 2];
        out[j++] = base64url_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 6) & 0x3F];
        out[j++] = base64url_alphabet[triple & 0x3F];
        i += 3;
    }
    if (remainder == 1)
    {
        uint32_t triple = ((uint32_t)data[i]) << 16;
        out[j++] = base64url_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 12) & 0x3F];
    }
    else if (remainder == 2)
    {
        uint32_t triple = (((uint32_t)data[i]) << 16) | (((uint32_t)data[i + 1]) << 8);
        out[j++] = base64url_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 6) & 0x3F];
    }

    out[j] = '\0';
    return (int)encoded_len;
}

/**
 * @brief Decode data from Base64 URL format (no padding) using the URL and
 * filename safe alphabet.
 *
 * @param in The input Base64 URL encoded string.
 * @param data_len The length of the input data.
 * @param out The buffer to store the decoded data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code
 *         indicating a null pointer, invalid input length, invalid character,
 * or insufficient buffer size.
 */
int multibase_base64_url_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    size_t in_len = data_len;
    size_t remainder = in_len % 4;
    if (remainder == 1)
    {
        return MULTIBASE_ERR_INVALID_INPUT_LEN;
    }
    size_t decoded_len = (in_len / 4) * 3;
    if (remainder == 2)
    {
        decoded_len += 1;
    }
    else if (remainder == 3)
    {
        decoded_len += 2;
    }
    if (out_len < decoded_len)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }
    static int8_t dtable[256];
    static int table_initialized = 0;
    if (!table_initialized)
    {
        int i;
        for (i = 0; i < 256; i++)
        {
            dtable[i] = -1;
        }
        for (i = 'A'; i <= 'Z'; i++)
        {
            dtable[i] = i - 'A';
        }
        for (i = 'a'; i <= 'z'; i++)
        {
            dtable[i] = i - 'a' + 26;
        }
        for (i = '0'; i <= '9'; i++)
        {
            dtable[i] = i - '0' + 52;
        }
        dtable[(unsigned char)'-'] = 62;
        dtable[(unsigned char)'_'] = 63;
        table_initialized = 1;
    }
    size_t i = 0;
    size_t j = 0;
    while (i + 4 <= in_len)
    {
        uint32_t vals[4];
        int k;
        for (k = 0; k < 4; k++)
        {
            char c = in[i++];
            if (c == '=')
            {
                vals[k] = 0;
            }
            else
            {
                int v = dtable[(unsigned char)c];
                if (v == -1)
                {
                    return MULTIBASE_ERR_INVALID_CHARACTER;
                }
                vals[k] = v;
            }
        }
        uint32_t triple = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        if (j < decoded_len)
        {
            out[j++] = (triple >> 16) & 0xFF;
        }
        if (j < decoded_len)
        {
            out[j++] = (triple >> 8) & 0xFF;
        }
        if (j < decoded_len)
        {
            out[j++] = triple & 0xFF;
        }
    }
    if (in_len % 4 != 0)
    {
        size_t rem = in_len % 4;
        uint32_t triple = 0;
        int k;
        for (k = 0; k < (int)rem; k++)
        {
            char c = in[i++];
            if (c == '=')
            {
                triple = triple << 6;
            }
            else
            {
                int v = dtable[(unsigned char)c];
                if (v == -1)
                {
                    return MULTIBASE_ERR_INVALID_CHARACTER;
                }
                triple = (triple << 6) | v;
            }
        }
        triple = triple << (6 * (4 - rem));
        if (rem == 2)
        {
            if (j < decoded_len)
            {
                out[j++] = (triple >> 16) & 0xFF;
            }
        }
        else if (rem == 3)
        {
            if (j < decoded_len)
            {
                out[j++] = (triple >> 16) & 0xFF;
            }
            if (j < decoded_len)
            {
                out[j++] = (triple >> 8) & 0xFF;
            }
        }
    }
    return (int)decoded_len;
}