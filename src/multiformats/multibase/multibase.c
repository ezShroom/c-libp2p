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

int multibase_encode
(
    multibase_t base,
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_len
)
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
            if (out_len < data_len * 2 + 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE16_CHARACTER;
            ret = base16_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE16_UPPER:
        {
            if (out_len < data_len * 2 + 2)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE16_UPPER_CHARACTER;
            ret = base16_upper_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE32:
        {
            size_t blocks = (data_len == 0) ? 0 : ((data_len + 4) / 5);
            size_t required = (blocks > 0 ? (blocks * 8 + 1) : 1) + 1;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE32_CHARACTER;
            ret = base32_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE32_UPPER:
        {
            size_t blocks = (data_len == 0) ? 0 : ((data_len + 4) / 5);
            size_t required = (blocks > 0 ? (blocks * 8 + 1) : 1) + 1;
            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }
            out[0] = BASE32_UPPER_CHARACTER;
            ret = base32_upper_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }
            return ret + 1;
        }
        case MULTIBASE_BASE58_BTC:
        case MULTIBASE_BASE64:
        case MULTIBASE_BASE64_URL:
        case MULTIBASE_BASE64_URL_PAD:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
        default:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
    }
}

int multibase_decode
(
    multibase_t base,
    const char *in,
    uint8_t *out,
    size_t out_len
)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    switch (base)
    {
        case MULTIBASE_BASE16:
        {
            if (in[0] != BASE16_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            size_t encoded_len = strlen(in + 1);
            return base16_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE16_UPPER:
        {
            if (in[0] != BASE16_UPPER_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            size_t encoded_len = strlen(in + 1);
            return base16_upper_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE32:
        {
            if (in[0] != BASE32_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            size_t encoded_len = strlen(in + 1);
            return base32_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE32_UPPER:
        {
            if (in[0] != BASE32_UPPER_CHARACTER)
            {
                return MULTIBASE_ERR_INVALID_CHARACTER;
            }
            size_t encoded_len = strlen(in + 1);
            return base32_upper_decode(in + 1, encoded_len, out, out_len);
        }
        case MULTIBASE_BASE58_BTC:
        case MULTIBASE_BASE64:
        case MULTIBASE_BASE64_URL:
        case MULTIBASE_BASE64_URL_PAD:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
        default:
        {
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
        }
    }
}