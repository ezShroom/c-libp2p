#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "multiformats/multibase/multibase.h"

/* Base58 (Bitcoin) character and Unicode value */
#define BASE58_BTC_CHARACTER 'z'
#define BASE58_BTC_UNICODE 0x007A

/* The base58 (Bitcoin) alphabet */
static const char base58_btc_alphabet[58] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * @brief Encode data into Base58 (Bitcoin) format.
 *
 * @param data The input data to be encoded.
 * @param data_len The length of the input data.
 * @param out The buffer to store the encoded Base58 string.
 * @param out_len The size of the output buffer.
 * @return The number of characters written to the output buffer, or an error code
 *         indicating a null pointer or insufficient buffer size.
 */
int base58_btc_encode(const uint8_t *data, size_t data_len, char *out, size_t out_len)
{
    if (data == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0)
    {
        zeros++;
    }

    size_t size = data_len * 138 / 100 + 1;
    uint8_t *b58 = (uint8_t *)malloc(size);
    if (b58 == NULL)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }
    memset(b58, 0, size);
    for (size_t i = zeros; i < data_len; i++)
    {
        int carry = data[i];
        for (int j = (int)size - 1; j >= 0; j--)
        {
            carry += 256 * b58[j];
            b58[j] = carry % 58;
            carry /= 58;
        }
    }

    size_t j = 0;
    while (j < size && b58[j] == 0)
    {
        j++;
    }

    size_t encoded_size = zeros + (size - j);
    if (out_len < encoded_size + 1)
    {
        free(b58);
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    size_t out_index = 0;
    for (size_t i = 0; i < zeros; i++)
    {
        out[out_index++] = '1';
    }

    for (; j < size; j++)
    {
        out[out_index++] = base58_btc_alphabet[b58[j]];
    }
    out[out_index] = '\0';
    free(b58);
    return (int)out_index;
}

/**
 * @brief Decode a Base58 (Bitcoin) encoded string into data.
 *
 * @param in The Base58 encoded input string.
 * @param data_len The length of the input data.
 * @param out The buffer to store the decoded data.
 * @param out_len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or an error code
 *         indicating a null pointer, invalid character, or insufficient buffer size.
 */
int base58_btc_decode(const char *in, size_t data_len, uint8_t *out, size_t out_len)
{
    if (in == NULL || out == NULL)
    {
        return MULTIBASE_ERR_NULL_POINTER;
    }

    size_t zeros = 0;
    while (zeros < data_len && in[zeros] == '1')
    {
        zeros++;
    }

    size_t size = data_len * 733 / 1000 + 1;
    uint8_t *b256 = (uint8_t *)malloc(size);
    if (b256 == NULL)
    {
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }
    memset(b256, 0, size);

    int map[128];
    for (int i = 0; i < 128; i++)
    {
        map[i] = -1;
    }
    for (int i = 0; i < 58; i++)
    {
        map[(int)base58_btc_alphabet[i]] = i;
    }

    for (size_t i = zeros; i < data_len; i++)
    {
        char c = in[i];
        if ((unsigned char)c & 0x80)
        {
            free(b256);
            return MULTIBASE_ERR_INVALID_CHARACTER;
        }
        int digit = map[(int)c];
        if (digit == -1)
        {
            free(b256);
            return MULTIBASE_ERR_INVALID_CHARACTER;
        }
        int carry = digit;
        for (int j = (int)size - 1; j >= 0; j--)
        {
            carry += 58 * b256[j];
            b256[j] = carry % 256;
            carry /= 256;
        }
        if (carry != 0)
        {
            free(b256);
            return MULTIBASE_ERR_INVALID_INPUT_LEN;
        }
    }

    size_t j = 0;
    while (j < size && b256[j] == 0)
    {
        j++;
    }

    size_t decoded_size = zeros + (size - j);
    if (out_len < decoded_size)
    {
        free(b256);
        return MULTIBASE_ERR_BUFFER_TOO_SMALL;
    }

    size_t out_index = 0;
    for (size_t i = 0; i < zeros; i++)
    {
        out[out_index++] = 0;
    }
    for (; j < size; j++)
    {
        out[out_index++] = b256[j];
    }
    free(b256);
    return (int)out_index;
}