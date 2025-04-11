#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multibase/encoding/base16.h"
#include "multiformats/multibase/encoding/base16_upper.h"
#include "multiformats/multibase/encoding/base32.h"
#include "multiformats/multibase/encoding/base32_upper.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multibase/encoding/base64.h"
#include "multiformats/multibase/encoding/base64_url.h"
#include "multiformats/multibase/encoding/base64_url_pad.h"
#include "multiformats/multibase/multibase.h"

/**
 * @brief Encode data using the specified multibase encoding.
 *
 * The output string is null terminated.
 *
 * @param base The multibase encoding to use.
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded output.
 * @param out_len The total size of the output buffer.
 * @return int The number of bytes written to the output buffer (excluding the null terminator), or a negative error code.
 */
int multibase_encode(multibase_t base, const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    int ret = 0;
    switch (base)
    {
        case MULTIBASE_BASE16:
        {
            if (data_len > (SIZE_MAX - 2) / 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t required = data_len * 2 + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE16_CHARACTER;
            ret = multibase_base16_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE16_UPPER:
        {
            if (data_len > (SIZE_MAX - 2) / 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t required = data_len * 2 + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE16_UPPER_CHARACTER;
            ret = multibase_base16_upper_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE32:
        {
            if (data_len > 5 * ((SIZE_MAX - 2) / 8))
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t blocks = (data_len == 0) ? 0 : ((data_len + 4) / 5);
            size_t encoded_len = (blocks > 0 ? blocks * 8 : 0);
            size_t required = 1 + encoded_len + 1;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE32_CHARACTER;
            ret = multibase_base32_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE32_UPPER:
        {
            if (data_len > 5 * ((SIZE_MAX - 2) / 8))
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t blocks = (data_len == 0) ? 0 : ((data_len + 4) / 5);
            size_t encoded_len = (blocks > 0 ? blocks * 8 : 0);
            size_t required = 1 + encoded_len + 1;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE32_UPPER_CHARACTER;
            ret = multibase_base32_upper_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE58_BTC:
        {
            if (out_len < 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE58_BTC_CHARACTER;
            ret = multibase_base58_btc_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE64:
        {
            if (data_len > 3 * ((SIZE_MAX - 2) / 4))
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t encoded_len = ((data_len + 2) / 3) * 4;
            size_t required = encoded_len + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE64_CHARACTER;
            ret = multibase_base64_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE64_URL:
        {
            if (data_len > 3 * ((SIZE_MAX - 2) / 4))
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t encoded_len = ((data_len + 2) / 3) * 4;
            size_t required = encoded_len + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE64_URL_CHARACTER;
            ret = multibase_base64_url_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        case MULTIBASE_BASE64_URL_PAD:
        {
            if (data_len > 3 * ((SIZE_MAX - 2) / 4))
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            size_t encoded_len = ((data_len + 2) / 3) * 4;
            size_t required = encoded_len + 2;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE64_URL_PAD_CHARACTER;
            ret = multibase_base64_url_pad_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            out[ret + 1] = '\0';
            return ret + 1;
        }
        default:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
    }
}

/**
 * @brief Decode a multibase-encoded string.
 *
 * The input string must be a valid null-terminated string beginning with the proper
 * multibase prefix.
 *
 * @param base The multibase encoding type.
 * @param in The input null-terminated string to be decoded.
 * @param out The buffer to store the decoded binary output.
 * @param out_len The size of the output buffer.
 * @return int The number of bytes decoded, or a negative error code.
 */
int multibase_decode(multibase_t base, const char *in, uint8_t *out, size_t out_len)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    if (in[0] == '\0')
    {
        return MULTIBASE_ERR_INVALID_CHARACTER;
    }

    size_t encoded_len = strlen(in + 1);

    switch (base)
    {
        case MULTIBASE_BASE16:
        {
            if (in[0] != BASE16_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base16_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE16_UPPER:
        {
            if (in[0] != BASE16_UPPER_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base16_upper_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE32:
        {
            if (in[0] != BASE32_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base32_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE32_UPPER:
        {
            if (in[0] != BASE32_UPPER_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base32_upper_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE58_BTC:
        {
            if (in[0] != BASE58_BTC_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base58_btc_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE64:
        {
            if (in[0] != BASE64_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base64_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE64_URL:
        {
            if (in[0] != BASE64_URL_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base64_url_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE64_URL_PAD:
        {
            if (in[0] != BASE64_URL_PAD_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            return multibase_base64_url_pad_decode(in + 1, encoded_len, out, out_len);
        }
        default:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
    }
}