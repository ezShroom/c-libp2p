#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/cid/cid_v1.h"
#include "multiformats/multibase/encoding/base16.h"
#include "multiformats/multibase/encoding/base32.h"
#include "multiformats/multibase/encoding/base58_btc.h"
#include "multiformats/multibase/encoding/base64.h"
#include "multiformats/multibase/encoding/base64_url.h"
#include "multiformats/multibase/encoding/base64_url_pad.h"
#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multicodec/multicodec_table.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

/**
 * @brief Detect the multibase encoding from the given string.
 *
 * @param str The input string to detect the multibase encoding from.
 * @return The detected multibase encoding.
 */
static multibase_t detect_multibase(const char *str)
{
    if (str == NULL || *str == '\0')
    {
        return MULTIBASE_BASE58_BTC;
    }
    switch (str[0])
    {
        case BASE58_BTC_CHARACTER:
            return MULTIBASE_BASE58_BTC;
        case BASE16_CHARACTER:
            return MULTIBASE_BASE16;
        case BASE32_CHARACTER:
            return MULTIBASE_BASE32;
        case BASE64_CHARACTER:
            return MULTIBASE_BASE64;
        case BASE64_URL_CHARACTER:
            return MULTIBASE_BASE64_URL;
        case BASE64_URL_PAD_CHARACTER:
            return MULTIBASE_BASE64_URL_PAD;
        default:
            return MULTIBASE_BASE58_BTC;
    }
}

/**
 * @brief Get the name of the multibase encoding.
 *
 * @param base The multibase encoding.
 * @return The name of the multibase encoding.
 */
static const char *get_multibase_name(multibase_t base)
{
    switch (base)
    {
        case MULTIBASE_BASE16:
            return "base16";
        case MULTIBASE_BASE16_UPPER:
            return "base16upper";
        case MULTIBASE_BASE32:
            return "base32";
        case MULTIBASE_BASE32_UPPER:
            return "base32upper";
        case MULTIBASE_BASE58_BTC:
            return "base58btc";
        case MULTIBASE_BASE64:
            return "base64";
        case MULTIBASE_BASE64_URL:
            return "base64url";
        case MULTIBASE_BASE64_URL_PAD:
            return "base64urlpad";
        default:
            return "unknown";
    }
}

/**
 * @brief Get the name of the multicodec from its code.
 *
 * @param code The multicodec code.
 * @return The name of the multicodec.
 */
static const char *get_multicodec_name(uint64_t code)
{
    for (size_t i = 0; i < multicodec_table_len; i++)
    {
        if (multicodec_table[i].code == code)
        {
            return multicodec_table[i].name;
        }
    }
    return "unknown";
}

/**
 * @brief Convert a multihash to a human-readable string.
 *
 * @param mh The input multihash.
 * @param mh_size The size of the input multihash.
 * @param out The output buffer to store the human-readable string.
 * @param out_len The size of the output buffer.
 * @return int Error code indicating success or type of failure.
 */
static int multihash_to_human(const uint8_t *mh, size_t mh_size, char *out, size_t out_len)
{
    if (mh == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    uint64_t hash_code = 0;
    size_t read = 0;
    if (unsigned_varint_decode(mh, mh_size, &hash_code, &read) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    if (read >= mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    uint64_t digest_len = 0;
    size_t read2 = 0;
    if (unsigned_varint_decode(mh + read, mh_size - read, &digest_len, &read2) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    size_t header_size = read + read2;
    if (header_size + digest_len != mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    const char *hash_name = get_multicodec_name(hash_code);
    size_t hex_len = digest_len * 2;
    char *hex_str = (char *)malloc(hex_len + 1);
    if (!hex_str)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }
    for (size_t i = 0; i < digest_len; i++)
    {
        sprintf(hex_str + i * 2, "%02x", mh[header_size + i]);
    }
    hex_str[hex_len] = '\0';
    int written = snprintf(out, out_len, "%s-%s", hash_name, hex_str);
    free(hex_str);

    if (written < 0 || (size_t)written >= out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    return written;
}

/**
 * @brief Compute the size of the human-readable string for a multihash.
 *
 * @param mh The input multihash.
 * @param mh_size The size of the input multihash.
 * @param out_size Pointer to store the size of the human-readable string.
 * @return int Error code indicating success or type of failure.
 */
static int compute_mh_human_size(const uint8_t *mh, size_t mh_size, size_t *out_size)
{
    if (mh == NULL || out_size == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    uint64_t hash_code = 0;
    size_t read = 0;
    if (unsigned_varint_decode(mh, mh_size, &hash_code, &read) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }
    if (read >= mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    uint64_t digest_len = 0;
    size_t read2 = 0;
    if (unsigned_varint_decode(mh + read, mh_size - read, &digest_len, &read2) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    size_t header_size = read + read2;
    if (header_size + digest_len != mh_size)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    const char *hash_name = get_multicodec_name(hash_code);
    *out_size = strlen(hash_name) + 1 + (digest_len * 2) + 1;
    return CIDV1_SUCCESS;
}

/**
 * @brief Initialize a CIDv1 structure.
 *
 * @param cid Pointer to the CIDv1 structure to initialize.
 * @param content_codec The content codec.
 * @param mh_data The multihash data.
 * @param mh_size The size of the multihash data.
 * @return int Error code indicating success or type of failure.
 */
int cid_v1_init(cid_v1_t *cid, uint64_t content_codec, const uint8_t *mh_data, size_t mh_size)
{
    if (cid == NULL || (mh_data == NULL && mh_size > 0))
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    cid->version = 1;
    cid->codec = content_codec;
    cid->multihash = NULL;
    cid->multihash_size = 0;

    if (mh_size > 0)
    {
        cid->multihash = (uint8_t *)malloc(mh_size);
        if (!cid->multihash)
        {
            return CIDV1_ERROR_ALLOCATION_FAILED;
        }
        memcpy(cid->multihash, mh_data, mh_size);
        cid->multihash_size = mh_size;
    }

    return CIDV1_SUCCESS;
}

/**
 * @brief Free the resources associated with a CIDv1 structure.
 *
 * @param cid Pointer to the CIDv1 structure to free.
 */
void cid_v1_free(cid_v1_t *cid)
{
    if (cid != NULL)
    {
        if (cid->multihash != NULL)
        {
            free(cid->multihash);
            cid->multihash = NULL;
        }
        cid->multihash_size = 0;
    }
}

/**
 * @brief Decode a CIDv1 structure from a byte array.
 *
 * @param cid Pointer to the CIDv1 structure to decode into.
 * @param data The input byte array.
 * @param data_len The length of the input byte array.
 * @return int Error code indicating success or type of failure.
 */
int cid_v1_from_bytes(cid_v1_t *cid, const uint8_t *data, size_t data_len)
{
    if (cid == NULL || data == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t offset = 0;
    uint64_t version = 0;
    size_t read = 0;
    if (unsigned_varint_decode(data, data_len, &version, &read) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }
    offset += read;
    if (version != 1)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    uint64_t codec = 0;
    size_t read2 = 0;
    if (unsigned_varint_decode(data + offset, data_len - offset, &codec, &read2) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_DECODE_FAILURE;
    }
    offset += read2;
    size_t mh_size = data_len - offset;
    if (mh_size == 0)
    {
        return CIDV1_ERROR_INVALID_ARG;
    }

    uint8_t *mh = (uint8_t *)malloc(mh_size);
    if (!mh)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }
    memcpy(mh, data + offset, mh_size);

    cid->version = version;
    cid->codec = codec;
    cid->multihash = mh;
    cid->multihash_size = mh_size;

    return offset + mh_size;
}

/**
 * @brief Encode a CIDv1 structure into a byte array.
 *
 * @param cid Pointer to the CIDv1 structure to encode.
 * @param out The output byte array.
 * @param out_len The length of the output byte array.
 * @return int Error code indicating success or type of failure.
 */
int cid_v1_to_bytes(const cid_v1_t *cid, uint8_t *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t pos = 0;
    size_t written = 0;
    size_t version_size = unsigned_varint_size(cid->version);
    if (pos + version_size > out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    if (unsigned_varint_encode(cid->version, out + pos, out_len - pos, &written) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_ENCODE_FAILURE;
    }
    pos += written;

    size_t codec_size = unsigned_varint_size(cid->codec);
    if (pos + codec_size > out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    if (unsigned_varint_encode(cid->codec, out + pos, out_len - pos, &written) != UNSIGNED_VARINT_OK)
    {
        return CIDV1_ERROR_ENCODE_FAILURE;
    }
    pos += written;

    if (pos + cid->multihash_size > out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(out + pos, cid->multihash, cid->multihash_size);
    pos += cid->multihash_size;

    return pos;
}

/**
 * @brief Encode a CIDv1 structure into a multibase-encoded string.
 *
 * @param cid Pointer to the CIDv1 structure to encode.
 * @param base The multibase encoding to use.
 * @param out The output string buffer.
 * @param out_len The length of the output string buffer.
 * @return int Error code indicating success or type of failure.
 */
int cid_v1_to_string(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t version_size = unsigned_varint_size(cid->version);
    size_t codec_size = unsigned_varint_size(cid->codec);
    size_t total_bin_size = version_size + codec_size + cid->multihash_size;

    uint8_t *tmp = (uint8_t *)malloc(total_bin_size);
    if (!tmp)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    int bin_len = cid_v1_to_bytes(cid, tmp, total_bin_size);
    if (bin_len < 0)
    {
        free(tmp);
        return bin_len;
    }

    int str_len = multibase_encode(base, tmp, bin_len, out, out_len);
    free(tmp);
    if (str_len < 0)
    {
        return CIDV1_ERROR_ENCODE_FAILURE;
    }

    return str_len;
}

/**
 * @brief Decode a CIDv1 structure from a multibase-encoded string.
 *
 * @param cid Pointer to the CIDv1 structure to decode into.
 * @param str The input multibase-encoded string.
 * @return int Error code indicating success or type of failure.
 */
int cid_v1_from_string(cid_v1_t *cid, const char *str)
{
    if (cid == NULL || str == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    size_t str_len = strlen(str);
    multibase_t base = detect_multibase(str);
    uint8_t *bin = (uint8_t *)malloc(str_len);

    if (!bin)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    int decoded_len = multibase_decode(base, str, bin, str_len);
    if (decoded_len < 0)
    {
        free(bin);
        return CIDV1_ERROR_DECODE_FAILURE;
    }

    int ret = cid_v1_from_bytes(cid, bin, decoded_len);
    free(bin);
    if (ret < 0)
    {
        return ret;
    }

    return (int)str_len;
}

/**
 * @brief Convert a CIDv1 structure to a human-readable string.
 *
 * @param cid Pointer to the CIDv1 structure to convert.
 * @param base The multibase encoding to use.
 * @param out The output string buffer.
 * @param out_len The length of the output string buffer.
 * @return int Error code indicating success or type of failure.
 */
int cid_v1_to_human(const cid_v1_t *cid, multibase_t base, char *out, size_t out_len)
{
    if (cid == NULL || out == NULL)
    {
        return CIDV1_ERROR_NULL_POINTER;
    }

    const char *mb_name = get_multibase_name(base);
    const char *codec_name = get_multicodec_name(cid->codec);

    size_t mh_human_size = 0;
    int err = compute_mh_human_size(cid->multihash, cid->multihash_size, &mh_human_size);
    if (err < 0)
    {
        return err;
    }

    char *mh_human = (char *)malloc(mh_human_size);
    if (!mh_human)
    {
        return CIDV1_ERROR_ALLOCATION_FAILED;
    }

    err = multihash_to_human(cid->multihash, cid->multihash_size, mh_human, mh_human_size);
    if (err < 0)
    {
        free(mh_human);
        return err;
    }

    int written = snprintf(out, out_len, "%s - cidv1 - %s - %s", mb_name, codec_name, mh_human);
    free(mh_human);

    if (written < 0 || (size_t)written >= out_len)
    {
        return CIDV1_ERROR_BUFFER_TOO_SMALL;
    }

    return written;
}