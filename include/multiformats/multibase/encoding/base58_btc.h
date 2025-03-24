#ifndef BASE58_BTC_H
#define BASE58_BTC_H

#include <stddef.h>
#include <stdint.h>
#include "multiformats/multibase/multibase.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The character used to represent Base58 (Bitcoin) encoding.
 */
#define BASE58_BTC_CHARACTER 'z'

/**
 * @brief Encode data into Base58 (Bitcoin) format.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base58 BTC string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer, or an error code.
 */
int base58_btc_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len);

/**
 * @brief Decode a Base58 (Bitcoin) encoded string.
 *
 * @param in The input Base58 BTC encoded string.
 * @param data_len The length of the input data.
 * @param out The buffer to store the decoded binary data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code.
 */
int base58_btc_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* BASE58_BTC_H */