#ifndef BASE32_UPPER_H
#define BASE32_UPPER_H

#include <stddef.h>
#include <stdint.h>
#include "multiformats/multibase/multibase.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The character used to represent Base32 uppercase encoding.
 */
#define BASE32_UPPER_CHARACTER 'B'

/**
 * @brief Encode data into Base32 format using uppercase letters.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base32 uppercase string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer, or an error code.
 */
int base32_upper_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len);

/**
 * @brief Decode a Base32 encoded string using uppercase letters.
 *
 * @param in The input Base32 uppercase encoded string.
 * @param data_len The length of the input Base32 uppercase encoded string.
 * @param out The buffer to store the decoded binary data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code.
 */
int base32_upper_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* BASE32_UPPER_H */