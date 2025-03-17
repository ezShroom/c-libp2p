#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "multiformats/multibase/multibase.h"

/* The base64 URL padding character and Unicode value */
#define BASE64_URL_PAD_CHARACTER 'U'
#define BASE64_URL_PAD_UNICODE 0x0055

/* The base64 URL alphabet (RFC 4648, Table 2) */
static const char base64url_alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * @brief Encode data into Base64 URL format with padding using the URL and filename safe alphabet.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base64 URL string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer, or an error code
 *         indicating a null pointer or insufficient buffer size.
 */
int base64_url_pad_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    size_t encoded_len = ((data_len + 2) / 3) * 4;
    if (out_len < encoded_len)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    size_t i = 0;
    size_t j = 0;
    while (i + 3 <= data_len)
    {
        uint32_t triple = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | ((uint32_t)data[i + 2]);
        out[j++] = base64url_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 6) & 0x3F];
        out[j++] = base64url_alphabet[triple & 0x3F];
        i += 3;
    }

    size_t remainder = data_len - i;
    if (remainder == 1)
    {
        uint32_t triple = ((uint32_t)data[i]) << 16;
        out[j++] = base64url_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 12) & 0x3F];
        out[j++] = BASE64_URL_PAD_CHARACTER;
        out[j++] = BASE64_URL_PAD_CHARACTER;
    }
    else if (remainder == 2)
    {
        uint32_t triple = (((uint32_t)data[i]) << 16) | (((uint32_t)data[i + 1]) << 8);
        out[j++] = base64url_alphabet[(triple >> 18) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 12) & 0x3F];
        out[j++] = base64url_alphabet[(triple >> 6) & 0x3F];
        out[j++] = BASE64_URL_PAD_CHARACTER;
    }
    return (int)encoded_len;
}

/**
 * @brief Decode data from Base64 URL format with padding using the URL and filename safe alphabet.
 *
 * @param in The input Base64 URL encoded string.
 * @param out The buffer to store the decoded data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code
 *         indicating a null pointer, invalid input length, invalid character, or insufficient buffer size.
 */
int base64_url_pad_decode(const char *in, uint8_t *out, size_t out_len)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    size_t in_len = strlen(in);
    if (in_len == 0)
    {
        return 0;
    }
    if (in_len % 4 != 0)
    {
        return MULTIBASE_ERR_INVALID_INPUT_LEN;
    }

    size_t pad_count = 0;
    if (in_len >= 1 && in[in_len - 1] == BASE64_URL_PAD_CHARACTER)
    {
        pad_count++;
    }
    if (in_len >= 2 && in[in_len - 2] == BASE64_URL_PAD_CHARACTER)
    {
        pad_count++;
    }

    size_t decoded_len = (in_len / 4) * 3 - pad_count;
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

    size_t groups = in_len / 4;
    size_t i = 0;
    size_t j = 0;
    if (groups > 0)
    {
        for (size_t group = 0; group < groups - 1; group++)
        {
            int v0 = dtable[(unsigned char)in[i++]];
            int v1 = dtable[(unsigned char)in[i++]];
            int v2 = dtable[(unsigned char)in[i++]];
            int v3 = dtable[(unsigned char)in[i++]];

            if (v0 == -1 || v1 == -1 || v2 == -1 || v3 == -1)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }

            uint32_t triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
            out[j++] = (triple >> 16) & 0xFF;
            out[j++] = (triple >> 8) & 0xFF;
            out[j++] = triple & 0xFF;
        }

        char c0 = in[i++];
        char c1 = in[i++];
        char c2 = in[i++];
        char c3 = in[i++];
        int v0 = dtable[(unsigned char)c0];
        int v1 = dtable[(unsigned char)c1];

        if (v0 == -1 || v1 == -1)
        {
            return MULTIBASE_ERR_INVALID_CHARACTER;
        }
        if (c2 == BASE64_URL_PAD_CHARACTER && c3 == BASE64_URL_PAD_CHARACTER)
        {
            uint32_t triple = (v0 << 18) | (v1 << 12);
            out[j++] = (triple >> 16) & 0xFF;
        }
        else if (c3 == BASE64_URL_PAD_CHARACTER)
        {
            int v2 = dtable[(unsigned char)c2];
            if (v2 == -1)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            uint32_t triple = (v0 << 18) | (v1 << 12) | (v2 << 6);
            out[j++] = (triple >> 16) & 0xFF;
            out[j++] = (triple >> 8) & 0xFF;
        }
        else
        {
            int v2 = dtable[(unsigned char)c2];
            int v3 = dtable[(unsigned char)c3];

            if (v2 == -1 || v3 == -1)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            
            uint32_t triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
            out[j++] = (triple >> 16) & 0xFF;
            out[j++] = (triple >> 8) & 0xFF;
            out[j++] = triple & 0xFF;
        }
    }
    return (int)decoded_len;
}