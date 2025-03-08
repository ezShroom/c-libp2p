#ifndef UNSIGNED_VARINT_H
#define UNSIGNED_VARINT_H

/**
 * @file unsigned_varint.h
 * @brief Provides functions to encode/decode 64-bit unsigned integers using
 *        the MSB-based unsigned varint format (max 9 bytes).
 *
 * The specification requires minimal encoding and disallows varints longer
 * than 9 bytes (63 bits). 
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @enum mf_varint_err_t
 * @brief Error codes for varint operations.
 */
typedef enum {
    MF_VARINT_OK = 0,          /**< No error. */
    MF_VARINT_ERR_BUFFER_OVER, /**< The buffer is not large enough. */
    MF_VARINT_ERR_TOO_LONG,    /**< Exceeded 9-byte (63-bit) practical maximum. */
    MF_VARINT_ERR_NOT_MINIMAL, /**< The encoding was not minimal. */
    MF_VARINT_ERR_VALUE_OVERFLOW /**< The decoded value does not fit in 63 bits. */
} mf_varint_err_t;

/**
 * @brief Encodes a 64-bit unsigned integer into a varint buffer.
 *
 * @param value  The 64-bit unsigned value to encode (up to 2^63-1 is safe under spec).
 * @param out    Pointer to the output buffer.
 * @param out_size The size of the @p out buffer in bytes.
 * @param written The number of bytes written to @p out (output parameter).
 *
 * @return MF_VARINT_OK on success, or MF_VARINT_ERR_BUFFER_OVER if @p out_size
 *         is too small to hold the encoded varint.
 *
 * @note The specification states a practical max of 9 bytes, so
 *       @p out must be at least 9 bytes to guarantee success for any
 *       valid 63-bit number.
 */
mf_varint_err_t mf_uvarint_encode(uint64_t value, 
                                  uint8_t *out, 
                                  size_t out_size, 
                                  size_t *written);

/**
 * @brief Decodes a varint from the given buffer into a 64-bit unsigned integer.
 *
 * @param in      Pointer to the input buffer containing varint data.
 * @param in_size The size of the @p in buffer in bytes.
 * @param value   Decoded 64-bit unsigned integer (output parameter).
 * @param read    The number of bytes read from @p in (output parameter).
 *
 * @return MF_VARINT_OK on success.
 *         MF_VARINT_ERR_TOO_LONG if more than 9 bytes are required.
 *         MF_VARINT_ERR_NOT_MINIMAL if the varint is not minimally encoded.
 *         MF_VARINT_ERR_VALUE_OVERFLOW if the value cannot fit in 63 bits.
 *         (Implementation-defined: if the buffer is truncated, might fail or
 *         need special handling.)
 */
mf_varint_err_t mf_uvarint_decode(const uint8_t *in, 
                                  size_t in_size, 
                                  uint64_t *value, 
                                  size_t *read);

/**
 * @brief Returns how many bytes are needed to encode the given 64-bit value as a varint.
 *
 * @param value  The 64-bit unsigned integer to measure.
 * @return       The number of bytes required (1..9).
 */
size_t mf_uvarint_size(uint64_t value);

#ifdef __cplusplus
}
#endif

#endif /* UNSIGNED_VARINT_H */