#ifndef MULTIBASE_H
#define MULTIBASE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Supported multibase encodings.
 */
typedef enum
{
    MULTIBASE_BASE16,
    MULTIBASE_BASE16_UPPER,
    MULTIBASE_BASE32,
    MULTIBASE_BASE32_UPPER,
    MULTIBASE_BASE58_BTC,
    MULTIBASE_BASE64,
    MULTIBASE_BASE64_URL,
    MULTIBASE_BASE64_URL_PAD
} multibase_t;

/**
 * Error codes for multibase operations.
 */
typedef enum
{
    MULTIBASE_SUCCESS = 0,
    MULTIBASE_ERR_NULL_POINTER = -1,
    MULTIBASE_ERR_INVALID_INPUT_LEN = -2,
    MULTIBASE_ERR_BUFFER_TOO_SMALL = -3,
    MULTIBASE_ERR_INVALID_CHARACTER = -4,
    MULTIBASE_ERR_UNSUPPORTED_BASE = -5,
    MULTIBASE_ERR_OVERFLOW = -6,
    MULTIBASE_ERR_INPUT_TOO_LARGE = -7
} multibase_error_t;

/**
 * @brief Encode data into a multibase string using the specified encoding.
 *
 * @param base       One of the MULTIBASE_BASE* values (e.g. MULTIBASE_BASE58_BTC).
 * @param data       Pointer to raw binary data to encode.
 * @param data_len   Number of bytes in `data`.
 * @param out        Buffer to write the resulting string (including prefix).
 * @param out_len    Size of `out` in bytes.
 * @return The number of characters written (excluding the terminating null byte) on success,
 *         or a negative value on error.
 */
int multibase_encode(multibase_t base, const uint8_t *data, size_t data_len, char *out,
                     size_t out_len);

/**
 * @brief Decode a multibase string (which includes the prefix) into binary data using the specified
 * encoding.
 *
 * @param base       One of the MULTIBASE_BASE* values indicating the expected encoding.
 * @param in         Null-terminated string with a multibase prefix.
 * @param out        Buffer for decoded bytes.
 * @param out_len    Size of `out` in bytes.
 * @return The number of bytes decoded on success,
 *         or a negative value on error.
 */
int multibase_decode(multibase_t base, const char *in, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* MULTIBASE_H */