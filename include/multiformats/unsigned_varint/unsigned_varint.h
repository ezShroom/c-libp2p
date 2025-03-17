#ifndef UNSIGNED_VARINT_H
#define UNSIGNED_VARINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @enum unsigned_varint_err_t
 * @brief Error codes for varint operations.
 */
typedef enum
{
    UNSIGNED_VARINT_OK                 =  0,  /**< No error. */
    UNSIGNED_VARINT_ERR_BUFFER_OVER    = -1,  /**< The buffer is not large enough. */
    UNSIGNED_VARINT_ERR_TOO_LONG       = -2,  /**< Exceeded 9-byte (63-bit) practical maximum. */
    UNSIGNED_VARINT_ERR_NOT_MINIMAL    = -3,  /**< The encoding was not minimal. */
    UNSIGNED_VARINT_ERR_VALUE_OVERFLOW = -4   /**< The decoded value does not fit in 63 bits. */
} unsigned_varint_err_t;

/**
 * @brief Encodes a 64-bit unsigned integer into a varint buffer.
 *
 * @param value  The 64-bit unsigned value to encode (up to 2^63-1 is safe under
 * spec).
 * @param out    Pointer to the output buffer.
 * @param out_size The size of the @p out buffer in bytes.
 * @param written The number of bytes written to @p out (output parameter).
 *
 * @return UNSIGNED_VARINT_OK on success, or UNSIGNED_VARINT_ERR_BUFFER_OVER if @p out_size
 *         is too small to hold the encoded varint.
 *
 * @note The specification states a practical max of 9 bytes, so
 *       @p out must be at least 9 bytes to guarantee success for any
 *       valid 63-bit number.
 */
unsigned_varint_err_t unsigned_varint_encode(uint64_t value, uint8_t *out, size_t out_size,
                                                size_t *written);

/**
 * @brief Decodes a varint from the given buffer into a 64-bit unsigned integer.
 *
 * @param in      Pointer to the input buffer containing varint data.
 * @param in_size The size of the @p in buffer in bytes.
 * @param value   Decoded 64-bit unsigned integer (output parameter).
 * @param read    The number of bytes read from @p in (output parameter).
 *
 * @return UNSIGNED_VARINT_OK on success.
 *         UNSIGNED_VARINT_ERR_TOO_LONG if more than 9 bytes are required or if
 *         the buffer ended but MSB was set (incomplete varint).
 *         UNSIGNED_VARINT_ERR_NOT_MINIMAL if the varint is not minimally encoded.
 *         UNSIGNED_VARINT_ERR_VALUE_OVERFLOW if the value cannot fit in 63 bits.
 */
unsigned_varint_err_t unsigned_varint_decode(const uint8_t *in, size_t in_size, uint64_t *value,
                                                size_t *read);

/**
 * @brief Returns how many bytes are needed to encode the given 64-bit value as
 * a varint.
 *
 * @param value  The 64-bit unsigned integer to measure.
 * @return       The number of bytes required (1..9).
 */
size_t unsigned_varint_size(uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* UNSIGNED_VARINT_H */