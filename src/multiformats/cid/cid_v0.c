#include <string.h>
#include "multiformats/cid/cid_v0.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multicodec/multicodec_codes.h"

/* Constants */
#define CIDV0_BINARY_SIZE (2 + CIDV0_HASH_SIZE)
#define CIDV0_STRING_LEN 46
#define SHA2_256_LENGTH_BYTE 0x20

/**
 * @brief Initialize a CIDv0 structure with a given digest.
 *
 * @param cid Pointer to the CIDv0 structure to initialize.
 * @param digest Pointer to the digest data.
 * @param digest_len Length of the digest data.
 * @return int Error code indicating success or type of failure.
 */
int cid_v0_init(cid_v0_t *cid, const uint8_t *digest, size_t digest_len)
{
    if (cid == NULL || digest == NULL)
    {
        return CIDV0_ERROR_NULL_POINTER;
    }
    if (digest_len != CIDV0_HASH_SIZE)
    {
        return CIDV0_ERROR_INVALID_DIGEST_LENGTH;
    }

    memcpy(cid->hash, digest, CIDV0_HASH_SIZE);
    return CIDV0_SUCCESS;
}

/**
 * @brief Convert a CIDv0 structure to its byte representation.
 *
 * @param cid Pointer to the CIDv0 structure.
 * @param out Buffer to store the byte representation.
 * @param out_len Length of the output buffer.
 * @return int Error code indicating success or type of failure.
 */
int cid_v0_to_bytes(const cid_v0_t *cid, uint8_t *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV0_ERROR_NULL_POINTER;
    }
    if (out_len < CIDV0_BINARY_SIZE)
    {
        return CIDV0_ERROR_BUFFER_TOO_SMALL;
    }

    out[0] = MULTICODEC_SHA2_256;
    out[1] = SHA2_256_LENGTH_BYTE;
    memcpy(out + 2, cid->hash, CIDV0_HASH_SIZE);
    return CIDV0_BINARY_SIZE;
}

/**
 * @brief Initialize a CIDv0 structure from its byte representation.
 *
 * @param cid Pointer to the CIDv0 structure to initialize.
 * @param bytes Byte representation of the CIDv0.
 * @param bytes_len Length of the byte representation.
 * @return int Error code indicating success or type of failure.
 */
int cid_v0_from_bytes(cid_v0_t *cid, const uint8_t *bytes, size_t bytes_len)
{
    if (cid == NULL || bytes == NULL)
    {
        return CIDV0_ERROR_NULL_POINTER;
    }
    if (bytes_len < CIDV0_BINARY_SIZE)
    {
        return CIDV0_ERROR_INVALID_DIGEST_LENGTH;
    }

    if (bytes[0] != MULTICODEC_SHA2_256 || bytes[1] != SHA2_256_LENGTH_BYTE)
    {
        return CIDV0_ERROR_INVALID_DIGEST_LENGTH;
    }

    memcpy(cid->hash, bytes + 2, CIDV0_HASH_SIZE);
    return CIDV0_BINARY_SIZE;
}

/**
 * @brief Convert a CIDv0 structure to its string representation using base58btc encoding.
 *
 * @param cid Pointer to the CIDv0 structure.
 * @param out Buffer to store the string representation.
 * @param out_len Length of the output buffer.
 * @return int Error code indicating success or type of failure.
 */
int cid_v0_to_string(const cid_v0_t *cid, char *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV0_ERROR_NULL_POINTER;
    }

    uint8_t bin[CIDV0_BINARY_SIZE];
    int bin_written = cid_v0_to_bytes(cid, bin, sizeof(bin));
    if (bin_written < 0)
    {
        return bin_written;
    }

    /* Encode using the multibase API with base58btc. */
    int str_written = base58_btc_encode(bin, CIDV0_BINARY_SIZE, out, out_len);
    if (str_written < 0)
    {
        return CIDV0_ERROR_ENCODE_FAILURE;
    }

    return str_written;
}

/**
 * @brief Initialize a CIDv0 structure from its string representation using base58btc decoding.
 *
 * @param cid Pointer to the CIDv0 structure to initialize.
 * @param str String representation of the CIDv0.
 * @return int Error code indicating success or type of failure.
 */
int cid_v0_from_string(cid_v0_t *cid, const char *str)
{
    if (cid == NULL || str == NULL)
    {
        return CIDV0_ERROR_NULL_POINTER;
    }

    size_t str_len = strlen(str);
    if (str_len != CIDV0_STRING_LEN || str[0] != 'Q' || str[1] != 'm')
    {
        return CIDV0_ERROR_DECODE_FAILURE;
    }

    uint8_t bin[CIDV0_BINARY_SIZE];
    int decoded_len = base58_btc_decode(str, str_len, bin, sizeof(bin));
    if (decoded_len < 0)
    {
        return CIDV0_ERROR_DECODE_FAILURE;
    }
    if (decoded_len != CIDV0_BINARY_SIZE)
    {
        return CIDV0_ERROR_DECODE_FAILURE;
    }

    if (bin[0] != MULTICODEC_SHA2_256 || bin[1] != SHA2_256_LENGTH_BYTE)
    {
        return CIDV0_ERROR_DECODE_FAILURE;
    }

    memcpy(cid->hash, bin + 2, CIDV0_HASH_SIZE);
    return CIDV0_STRING_LEN;
}