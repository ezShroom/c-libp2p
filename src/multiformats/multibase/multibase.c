#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "multiformats/multibase/multibase.h"
#include "multiformats/multibase/base16.h"
#include "multiformats/multibase/base16_upper.h"
#include "multiformats/multibase/base32.h"
#include "multiformats/multibase/base32_upper.h"
#include "multiformats/multibase/base58_btc.h"
#include "multiformats/multibase/base64.h"
#include "multiformats/multibase/base64_url.h"
#include "multiformats/multibase/base64_url_pad.h"

/**
 * @brief Encode data into a multibase string using the specified encoding.
 *
 * @param base The multibase encoding to use.
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the resulting multibase string (including prefix).
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer (excluding the terminating null byte),
 *         or a negative error code indicating a null pointer, insufficient buffer size, or unsupported base.
 */
int multibase_encode(
    multibase_t base,
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_len)
{
    int ret;
    if ((data == NULL) || (out == NULL))
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    switch (base)
    {
        case MULTIBASE_BASE16:
        {
            /* The base16 function requires a temporary buffer of size (data_len * 2 + 1)
             * and we need one extra byte for the prefix. */
            size_t required = data_len * 2 + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = 'f';
            {
                size_t temp_buf_size = data_len * 2 + 1;
                char *temp = malloc(temp_buf_size);
                if (temp == NULL)
                {
                    return MULTIBASE_ERR_NULL_POINTER;
                }
                ret = base16_encode(data, data_len, temp, temp_buf_size);
                if (ret < 0)
                {
                    free(temp);
                    return ret;
                }
                memcpy(out + 1, temp, ret);
                free(temp);
            }
            return ret + 1;
        }
        case MULTIBASE_BASE16_UPPER:
        {
            size_t required = data_len * 2 + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = 'F';
            {
                size_t temp_buf_size = data_len * 2 + 1;
                char *temp = malloc(temp_buf_size);
                if (temp == NULL)
                {
                    return MULTIBASE_ERR_NULL_POINTER;
                }
                ret = base16_upper_encode(data, data_len, temp, temp_buf_size);
                if (ret < 0)
                {
                    free(temp);
                    return ret;
                }
                memcpy(out + 1, temp, ret);
                free(temp);
            }
            return ret + 1;
        }
        case MULTIBASE_BASE32:
        {
            ret = base32_encode(data, data_len, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE32_UPPER:
        {
            ret = base32_upper_encode(data, data_len, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE58_BTC:
        {
            if (out_len < 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = 'z';
            ret = base58_btc_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE64:
        {
            if (out_len < 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = 'm';
            ret = base64_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE64_URL:
        {
            if (out_len < 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = 'u';
            ret = base64_url_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE64_URL_PAD:
        {
            if (out_len < 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = 'U';
            ret = base64_url_pad_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        default:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
    }
}

/**
 * @brief Decode a multibase string (which includes the prefix) into binary data using the specified encoding.
 *
 * @param base The multibase encoding that the input string is expected to use.
 * @param in Null-terminated multibase string to be decoded.
 * @param out Buffer to store the decoded binary data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes decoded on success, or a negative error code indicating a null pointer,
 *         invalid input length, invalid character, or unsupported base.
 */
int multibase_decode(
    multibase_t base,
    const char *in,
    uint8_t *out,
    size_t out_len)
{
    int ret;
    if ((in == NULL) || (out == NULL))
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }
    if (in[0] == '\0')
    {
        return MULTIBASE_ERR_INVALID_INPUT_LEN;
    }
    switch (base)
    {
        case MULTIBASE_BASE16:
        {
            if (in[0] != 'f')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base16_decode(in + 1, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE16_UPPER:
        {
            if (in[0] != 'F')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base16_upper_decode(in + 1, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE32:
        {
            if (in[0] != 'b')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base32_decode(in, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE32_UPPER:
        {
            if (in[0] != 'B')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base32_upper_decode(in, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE58_BTC:
        {
            if (in[0] != 'z')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base58_btc_decode(in + 1, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE64:
        {
            if (in[0] != 'm')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base64_decode(in + 1, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE64_URL:
        {
            if (in[0] != 'u')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base64_url_decode(in + 1, out, out_len);
            return ret;
        }
        case MULTIBASE_BASE64_URL_PAD:
        {
            if (in[0] != 'U')
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            ret = base64_url_pad_decode(in + 1, out, out_len);
            return ret;
        }
        default:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
    }
}