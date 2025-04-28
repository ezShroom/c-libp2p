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
 * @brief Validate that (len * mul + add) will not overflow size_t.
 *
 * The macro returns MULTIBASE_ERR_INPUT_TOO_LARGE from the calling function
 * if the multiplication / addition could overflow.
 */
#define MB_CHECK_ENC_LEN(len, mul, add)                                                                                                              \
    do                                                                                                                                               \
    {                                                                                                                                                \
        if ((len) > (SIZE_MAX - (add)) / (mul))                                                                                                      \
            return MULTIBASE_ERR_INPUT_TOO_LARGE;                                                                                                    \
    } while (0)

static inline size_t base32_encoded_len(size_t n)
{
    if (n == 0)
    {
        return 0;
    }

    if (n > SIZE_MAX - 4)
    {
        return SIZE_MAX;
    }

    size_t blocks = (n + 4) / 5;
    if (blocks > SIZE_MAX / 8)
    {
        return SIZE_MAX;
    }
    return blocks * 8;
}

/**
 * Compute   ceil(n / 3) * 4   without overflowing SIZE_MAX.
 * Returns SIZE_MAX on overflow.
 */
static inline size_t base64_encoded_len(size_t n)
{
    if (n > SIZE_MAX - 2)
    {
        return SIZE_MAX;
    }

    size_t tmp = (n + 2) / 3;
    if (tmp > SIZE_MAX / 4)
    {
        return SIZE_MAX;
    }
    return tmp * 4;
}

/**
 * Worst-case Base58/BTC length: ceil(n * 138 / 100)
 * The factor 138/100 is an upper-bound for log256/log58.
 *
 * Returns SIZE_MAX on overflow.
 */
static inline size_t base58btc_encoded_len(size_t n)
{
    if (n > (SIZE_MAX - 99) / 138)
    {
        return SIZE_MAX;
    }
    return (n * 138 + 99) / 100;
}

/**
 * @brief Encode data using the specified multibase encoding.
 *
 * The output string is null terminated.
 *
 * @param base     The multibase encoding to use.
 * @param data     The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out      The buffer to store the encoded output.
 * @param out_len  The total size of the output buffer.
 * @return ptrdiff_t
 *         The number of bytes written to the output buffer (excluding the
 *         null terminator), or a negative error code.
 */
ptrdiff_t multibase_encode(multibase_t base, const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    ptrdiff_t ret = 0;

    switch (base)
    {
        case MULTIBASE_BASE16:
        {
            MB_CHECK_ENC_LEN(data_len, 2, 2); /* 2 × data + prefix + NUL */
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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE16_UPPER:
        {
            MB_CHECK_ENC_LEN(data_len, 2, 2);
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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE32:
        {
            size_t encoded_len = base32_encoded_len(data_len);
            if (encoded_len == SIZE_MAX)
            {
                return MULTIBASE_ERR_INPUT_TOO_LARGE;
            }

            size_t required = 1 + encoded_len + 1; /* prefix + data + NUL */

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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE32_UPPER:
        {
            size_t encoded_len = base32_encoded_len(data_len);
            if (encoded_len == SIZE_MAX)
            {
                return MULTIBASE_ERR_INPUT_TOO_LARGE;
            }

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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE58_BTC:
        {
            size_t encoded_len = base58btc_encoded_len(data_len);
            if (encoded_len == SIZE_MAX)
            {
                return MULTIBASE_ERR_INPUT_TOO_LARGE;
            }

            size_t required = 1 + encoded_len + 1;

            if (out_len < required)
            {
                return MULTIBASE_ERR_BUFFER_TOO_SMALL;
            }

            out[0] = BASE58_BTC_CHARACTER;
            ret = multibase_base58_btc_encode(data, data_len, out + 1, out_len - 1);
            if (ret < 0)
            {
                return ret;
            }

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE64:
        {
            size_t encoded_len = base64_encoded_len(data_len);
            if (encoded_len == SIZE_MAX)
            {
                return MULTIBASE_ERR_INPUT_TOO_LARGE;
            }

            size_t required = 1 + encoded_len + 1;

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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE64_URL:
        {
            size_t encoded_len = base64_encoded_len(data_len);
            if (encoded_len == SIZE_MAX)
            {
                return MULTIBASE_ERR_INPUT_TOO_LARGE;
            }

            size_t required = 1 + encoded_len + 1;

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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }
        case MULTIBASE_BASE64_URL_PAD:
        {
            size_t encoded_len = base64_encoded_len(data_len);
            if (encoded_len == SIZE_MAX)
            {
                return MULTIBASE_ERR_INPUT_TOO_LARGE;
            }

            size_t required = 1 + encoded_len + 1;

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

            size_t written = (size_t)ret;
            out[written + 1] = '\0';
            return (ptrdiff_t)written + 1;
        }

        default:
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
    }
}

/**
 * @brief Decode a multibase-encoded string.
 *
 * The input string must be a valid null-terminated string beginning with the proper
 * multibase prefix.
 *
 * @param base    The multibase encoding type.
 * @param in      The input null-terminated string to be decoded.
 * @param out     The buffer to store the decoded binary output.
 * @param out_len The size of the output buffer.
 * @return ptrdiff_t
 *         The number of bytes decoded, or a negative error code.
 */
ptrdiff_t multibase_decode(multibase_t base, const char *in, uint8_t *out, size_t out_len)
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
    if (encoded_len > (size_t)PTRDIFF_MAX)
    {
        return MULTIBASE_ERR_INPUT_TOO_LARGE;
    }

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
            return MULTIBASE_ERR_UNSUPPORTED_BASE;
    }
}