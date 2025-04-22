#include <ctype.h>
#include <limits.h>
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
#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ecdsa.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_rsa.h"
#include "peer_id/peer_id_secp256k1.h"

/* Constants */
#define PEER_ID_IDENTITY_HASH_MAX_SIZE 42
#define PEER_ID_MAX_PUBKEY_LEN (64 * 1024)

/**
 * @brief Extract the length of the multihash digest from a buffer.
 *
 * This function decodes the multihash buffer to determine the length of the digest.
 *
 * @param mh_buf The buffer containing the multihash data.
 * @param mh_size The size of the multihash buffer.
 * @param digest_len Pointer to store the extracted digest length.
 * @return 0 on success, -1 on failure (e.g., invalid buffer or decoding error).
 */
static int extract_multihash_digest_length(const uint8_t *mh_buf, size_t mh_size, size_t *digest_len)
{
    if (!mh_buf || !digest_len)
    {
        return -1;
    }

    if (mh_size < 2)
    {
        return -1;
    }

    uint64_t hash_func_code;
    size_t hash_code_size;
    unsigned_varint_err_t err = unsigned_varint_decode(mh_buf, mh_size, &hash_func_code, &hash_code_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }

    uint64_t len;
    size_t len_size;
    err = unsigned_varint_decode(mh_buf + hash_code_size, mh_size - hash_code_size, &len, &len_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }

    if (hash_code_size + len_size + len > mh_size)
    {
        return -1;
    }

    *digest_len = (size_t)len;
    return 0;
}

/**
 * @brief Check if a string starts with a given prefix.
 *
 * This function checks whether the provided string begins with the specified prefix.
 *
 * @param str The string to be checked.
 * @param prefix The prefix to check against the string.
 * @return 1 if the string starts with the prefix, 0 otherwise.
 */
static int starts_with(const char *str, const char *prefix)
{
    if (!str || !prefix)
    {
        return 0;
    }

    size_t prefix_len = strlen(prefix);
    size_t str_len = strlen(str);

    if (str_len < prefix_len)
    {
        return 0;
    }

    return strncmp(str, prefix, prefix_len) == 0;
}

/**
 * @brief Determine the multibase type from a given prefix character.
 *
 * This function maps a prefix character to its corresponding multibase type.
 * If the prefix character does not match any known multibase type, it returns -1.
 *
 * @param prefix The character representing the multibase prefix.
 * @return The corresponding multibase type, or -1 if the prefix is unrecognized.
 */
static multibase_t multibase_from_prefix(char prefix)
{
    switch (prefix)
    {
        case BASE32_CHARACTER:
            return MULTIBASE_BASE32;
        case BASE32_UPPER_CHARACTER:
            return MULTIBASE_BASE32_UPPER;
        case BASE58_BTC_CHARACTER:
            return MULTIBASE_BASE58_BTC;
        case BASE64_CHARACTER:
            return MULTIBASE_BASE64;
        case BASE64_URL_CHARACTER:
            return MULTIBASE_BASE64_URL;
        case BASE64_URL_PAD_CHARACTER:
            return MULTIBASE_BASE64_URL_PAD;
        case BASE16_CHARACTER:
            return MULTIBASE_BASE16;
        case BASE16_UPPER_CHARACTER:
            return MULTIBASE_BASE16_UPPER;
        default:
            return (multibase_t)-1;
    }
}

/**
 * @brief Create a peer ID from a public key.
 *
 * This function generates a peer ID based on the provided public key buffer.
 * It validates the input parameters and initializes the peer ID structure.
 *
 * @param pubkey_buf The buffer containing the public key.
 * @param pubkey_len The length of the public key buffer.
 * @param pid Pointer to the peer ID structure to be initialized.
 * @return peer_id_error_t Error code indicating success or type of failure.
 */
peer_id_error_t peer_id_create_from_public_key(const uint8_t *pubkey_buf, size_t pubkey_len, peer_id_t *pid)
{
    if (!pubkey_buf || !pid)
    {
        return PEER_ID_E_NULL_PTR;
    }

    if (pubkey_len > PEER_ID_MAX_PUBKEY_LEN)
    {
        return PEER_ID_E_BUFFER_TOO_SMALL;
    }

    // Initialize output
    pid->bytes = NULL;
    pid->size = 0;

    // Parse the public-key protobuf
    uint64_t key_type = 0;
    const uint8_t *key_data = NULL;
    size_t key_data_len = 0;
    int parse_result = parse_public_key_proto(pubkey_buf, pubkey_len, &key_type, &key_data, &key_data_len);
    if (parse_result < 0)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    // Choose hash function code
    uint64_t hash_function_code;
    if (pubkey_len <= PEER_ID_IDENTITY_HASH_MAX_SIZE)
    {
        hash_function_code = MULTICODEC_IDENTITY;
    }
    else
    {
        hash_function_code = MULTICODEC_SHA2_256;
    }

    // Compute varint sizes
    size_t hash_code_size = unsigned_varint_size(hash_function_code);
    size_t digest_len_size = unsigned_varint_size((hash_function_code == MULTICODEC_IDENTITY) ? pubkey_len : 32);
    size_t payload_len = (hash_function_code == MULTICODEC_IDENTITY) ? pubkey_len : 32;
    if (payload_len > SIZE_MAX - hash_code_size - digest_len_size)
    {
        return PEER_ID_E_BUFFER_TOO_SMALL;
    }

    size_t max_multihash_size = hash_code_size + digest_len_size + ((hash_function_code == MULTICODEC_IDENTITY) ? pubkey_len : 32);

    pid->bytes = (uint8_t *)malloc(max_multihash_size);
    if (!pid->bytes)
    {
        return PEER_ID_E_ALLOC_FAILED;
    }

    int result = multihash_encode(hash_function_code, pubkey_buf, pubkey_len, pid->bytes, max_multihash_size);
    if (result < 0)
    {
        free(pid->bytes);
        pid->bytes = NULL;
        pid->size = 0;
        switch (result)
        {
            case MULTIHASH_ERR_NULL_POINTER:
                return PEER_ID_E_NULL_PTR;
            case MULTIHASH_ERR_INVALID_INPUT:
                return PEER_ID_E_INVALID_PROTOBUF;
            case MULTIHASH_ERR_UNSUPPORTED_FUN:
                return PEER_ID_E_UNSUPPORTED_KEY;
            case MULTIHASH_ERR_DIGEST_TOO_LARGE:
                return PEER_ID_E_BUFFER_TOO_SMALL;
            case MULTIHASH_ERR_ALLOC_FAILURE:
                return PEER_ID_E_ALLOC_FAILED;
            default:
                return PEER_ID_E_CRYPTO_FAILED;
        }
    }

    pid->size = result;
    return PEER_ID_SUCCESS;
}

/**
 * @brief Create a peer ID from a private key.
 *
 * This function generates a peer ID from a given private key buffer. It supports
 * multiple key types, including RSA, Ed25519, secp256k1, and ECDSA. The function
 * first parses the private key to determine its type and then derives the corresponding
 * public key. Finally, it creates a peer ID from the public key.
 *
 * @param privkey_buf The buffer containing the private key.
 * @param privkey_len The length of the private key buffer.
 * @param pid Pointer to the peer_id_t structure where the resulting peer ID will be stored.
 * @return peer_id_error_t Error code indicating success or type of failure.
 */
peer_id_error_t peer_id_create_from_private_key(const uint8_t *privkey_buf, size_t privkey_len, peer_id_t *pid)
{
    if (!privkey_buf || !pid)
    {
        return PEER_ID_E_NULL_PTR;
    }

    pid->bytes = NULL;
    pid->size = 0;

    uint64_t key_type = 0;
    const uint8_t *key_data = NULL;
    size_t key_data_len = 0;
    int parse_result = parse_private_key_proto(privkey_buf, privkey_len, &key_type, &key_data, &key_data_len);
    if (parse_result < 0)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    uint8_t *pubkey_buf = NULL;
    size_t pubkey_len = 0;
    peer_id_error_t ret;
    switch (key_type)
    {
        case 0:
            ret = peer_id_create_from_private_key_rsa(key_data, key_data_len, &pubkey_buf, &pubkey_len);
            break;
        case 1:
            ret = peer_id_create_from_private_key_ed25519(key_data, key_data_len, &pubkey_buf, &pubkey_len);
            break;
        case 2:
            ret = peer_id_create_from_private_key_secp256k1(key_data, key_data_len, &pubkey_buf, &pubkey_len);
            break;
        case 3:
            ret = peer_id_create_from_private_key_ecdsa(key_data, key_data_len, &pubkey_buf, &pubkey_len);
            break;
        default:
            return PEER_ID_E_UNSUPPORTED_KEY;
    }

    if (ret != PEER_ID_SUCCESS)
    {
        return ret;
    }

    ret = peer_id_create_from_public_key(pubkey_buf, pubkey_len, pid);
    free(pubkey_buf);
    return ret;
}

/**
 * @brief Encode a peer ID into a specified format.
 *
 * This function encodes a given peer ID into a specified format, such as
 * multibase or CIDv1. It handles different encoding scenarios and ensures
 * that the output buffer is appropriately sized and populated.
 *
 * @param pid The peer ID to be encoded.
 * @param format The format to encode the peer ID into.
 * @param out The buffer to store the encoded peer ID.
 * @param out_size The size of the output buffer.
 * @return int The size of the encoded peer ID, or an error code indicating
 *         the type of failure.
 */
peer_id_error_t peer_id_create_from_string(const char *str, peer_id_t *pid)
{
    if (!str || !pid)
    {
        return PEER_ID_E_NULL_PTR;
    }

    pid->bytes = NULL;
    pid->size = 0;

    if (starts_with(str, "Qm") || starts_with(str, "1"))
    {
        size_t input_len = strlen(str);

        if (input_len > SIZE_MAX - 2)
        {
            return PEER_ID_E_BUFFER_TOO_SMALL;
        }

        char *prefixed_str = (char *)malloc(input_len + 2);
        if (!prefixed_str)
        {
            return PEER_ID_E_ALLOC_FAILED;
        }

        prefixed_str[0] = BASE58_BTC_CHARACTER;
        strcpy(prefixed_str + 1, str);

        size_t max_decoded_size = input_len;
        uint8_t *decoded = (uint8_t *)malloc(max_decoded_size);
        if (!decoded)
        {
            free(prefixed_str);
            return PEER_ID_E_ALLOC_FAILED;
        }

        int result = multibase_decode(MULTIBASE_BASE58_BTC, prefixed_str, decoded, max_decoded_size);
        free(prefixed_str);
        if (result < 0)
        {
            free(decoded);
            return PEER_ID_E_ENCODING_FAILED;
        }

        size_t digest_len;
        if (extract_multihash_digest_length(decoded, result, &digest_len) < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        uint8_t *digest = (uint8_t *)malloc(digest_len);
        if (!digest)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        uint64_t hash_func_code;
        size_t actual_digest_len = digest_len;
        int mh_result = multihash_decode(decoded, result, &hash_func_code, digest, &actual_digest_len);
        free(digest);
        if (mh_result < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        pid->bytes = (uint8_t *)malloc(result);
        if (!pid->bytes)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        memcpy(pid->bytes, decoded, result);
        pid->size = result;
        free(decoded);
        return PEER_ID_SUCCESS;
    }
    else if (isalnum((unsigned char)str[0]))
    {
        multibase_t base = multibase_from_prefix(str[0]);
        if (base == (multibase_t)-1)
        {
            return PEER_ID_E_INVALID_STRING;
        }

        size_t input_len = strlen(str);
        size_t max_decoded_size = input_len;
        uint8_t *decoded = (uint8_t *)malloc(max_decoded_size);
        if (!decoded)
        {
            return PEER_ID_E_ALLOC_FAILED;
        }

        int result = multibase_decode(base, str, decoded, max_decoded_size);
        if (result < 0)
        {
            free(decoded);
            return PEER_ID_E_ENCODING_FAILED;
        }

        if (result < 2 || decoded[0] != MULTICODEC_CIDV1)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        uint64_t multicodec_code;
        size_t codec_size;
        unsigned_varint_err_t varint_result = unsigned_varint_decode(decoded + 1, result - 1, &multicodec_code, &codec_size);
        if (varint_result != UNSIGNED_VARINT_OK || multicodec_code != MULTICODEC_LIBP2P_KEY)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        size_t multihash_offset = 1 + codec_size;
        if (multihash_offset >= result)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        size_t digest_len;
        if (extract_multihash_digest_length(decoded + multihash_offset, result - multihash_offset, &digest_len) < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        uint8_t *digest = (uint8_t *)malloc(digest_len);
        if (!digest)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        uint64_t hash_func_code;
        size_t actual_digest_len = digest_len;
        int mh_result = multihash_decode(decoded + multihash_offset, result - multihash_offset, &hash_func_code, digest, &actual_digest_len);
        free(digest);
        if (mh_result < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        size_t peerid_len = result - multihash_offset;
        pid->bytes = (uint8_t *)malloc(peerid_len);
        if (!pid->bytes)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        memcpy(pid->bytes, decoded + multihash_offset, peerid_len);
        pid->size = peerid_len;
        free(decoded);
        return PEER_ID_SUCCESS;
    }
    else
    {
        return PEER_ID_E_INVALID_STRING;
    }
}

/**
 * @brief Convert a peer ID to a string representation.
 *
 * This function converts a peer ID into a string format based on the specified
 * format type. It supports different encoding formats such as Base58 and Multibase CIDv1.
 *
 * @param pid Pointer to the peer_id_t structure containing the peer ID.
 * @param format The desired output format for the peer ID string.
 * @param out The buffer to store the resulting string representation of the peer ID.
 * @param out_size The size of the output buffer.
 * @return int Error code indicating success or type of failure.
 */
int peer_id_to_string(const peer_id_t *pid, peer_id_format_t format, char *out, size_t out_size)
{
    if (!pid || !pid->bytes || !out)
    {
        return PEER_ID_E_NULL_PTR;
    }
    if (out_size == 0)
    {
        return PEER_ID_E_BUFFER_TOO_SMALL;
    }

    if (format == PEER_ID_FMT_BASE58_LEGACY)
    {
        int result = multibase_encode(MULTIBASE_BASE58_BTC, pid->bytes, pid->size, out, out_size);
        if (result < 0)
        {
            return PEER_ID_E_ENCODING_FAILED;
        }
        if (result > 1 && out[0] == BASE58_BTC_CHARACTER)
        {
            memmove(out, out + 1, result);
            out[result - 1] = '\0';
            return result - 1;
        }
        return result;
    }
    else if (format == PEER_ID_FMT_MULTIBASE_CIDv1)
    {
        size_t varint_size = unsigned_varint_size(MULTICODEC_LIBP2P_KEY);

        if (pid->size > SIZE_MAX - 1 - varint_size)
        {
            return PEER_ID_E_BUFFER_TOO_SMALL;
        }

        size_t cid_size = 1 + varint_size + pid->size;
        uint8_t *cid = (uint8_t *)malloc(cid_size);
        if (!cid)
        {
            return PEER_ID_E_ALLOC_FAILED;
        }

        cid[0] = MULTICODEC_CIDV1;
        size_t written;
        if (unsigned_varint_encode(MULTICODEC_LIBP2P_KEY, cid + 1, varint_size, &written) != UNSIGNED_VARINT_OK)
        {
            free(cid);
            return PEER_ID_E_ENCODING_FAILED;
        }
        memcpy(cid + 1 + written, pid->bytes, pid->size);

        int result = multibase_encode(MULTIBASE_BASE32, cid, 1 + written + pid->size, out, out_size);
        free(cid);
        if (result < 0)
        {
            return PEER_ID_E_ENCODING_FAILED;
        }
        return result;
    }
    else
    {
        return PEER_ID_E_ENCODING_FAILED;
    }
}

/**
 * @brief Compare two peer IDs for equality.
 *
 * This function checks if two peer IDs are equal by comparing their byte arrays.
 * It performs a constant-time comparison to prevent timing attacks.
 *
 * @param a The first peer ID to compare.
 * @param b The second peer ID to compare.
 * @return int Returns 1 if the peer IDs are equal, 0 if they are not, and -1 if
 *         either of the peer IDs is invalid (e.g., null pointers or uninitialized bytes).
 */
int peer_id_equals(const peer_id_t *a, const peer_id_t *b)
{
    if (!a || !b || !a->bytes || !b->bytes)
    {
        return -1;
    }
    if (a->size != b->size)
    {
        return 0;
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < a->size; i++)
    {
        diff |= a->bytes[i] ^ b->bytes[i];
    }
    return diff == 0;
}

/**
 * @brief Destroy a peer ID.
 *
 * This function deallocates the memory associated with a peer ID's byte array
 * and resets its size to zero. It ensures that the peer ID is properly cleaned up
 * to prevent memory leaks.
 *
 * @param pid Pointer to the peer ID to be destroyed. If the pointer or its byte array
 *            is NULL, the function does nothing.
 */
void peer_id_destroy(peer_id_t *pid)
{
    if (pid && pid->bytes)
    {
        free(pid->bytes);
        pid->bytes = NULL;
        pid->size = 0;
    }
}