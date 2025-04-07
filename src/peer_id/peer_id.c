#include <ctype.h>
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

// Constants
#define PEER_ID_IDENTITY_HASH_MAX_SIZE 42 // Maximum size for using identity multihash

// Helper function to extract just the digest length from a multihash without fully decoding it
static int extract_multihash_digest_length(const uint8_t *mh_buf, size_t mh_size,
                                           size_t *digest_len)
{
    if (!mh_buf || !digest_len)
    {
        return -1;
    }

    if (mh_size < 2)
    { // Need at least hash function code and digest length
        return -1;
    }

    // Decode the hash function code varint
    uint64_t hash_func_code;
    size_t hash_code_size;
    unsigned_varint_err_t err =
        unsigned_varint_decode(mh_buf, mh_size, &hash_func_code, &hash_code_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }

    // Decode the digest length varint
    uint64_t len;
    size_t len_size;
    err =
        unsigned_varint_decode(mh_buf + hash_code_size, mh_size - hash_code_size, &len, &len_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }

    // Ensure the digest length fits within the provided buffer
    if (hash_code_size + len_size + len > mh_size)
    {
        return -1;
    }

    *digest_len = (size_t)len;
    return 0;
}

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

// Helper function to get the multibase encoding type from a prefix character
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
        case BASE64_URL_CHARACTER:
            return MULTIBASE_BASE64_URL;
        case BASE64_URL_PAD_CHARACTER:
            return MULTIBASE_BASE64_URL_PAD;
        default:
            return (multibase_t)-1; // Invalid or unsupported base
    }
}

/*
 * Minimal parser for a PublicKey protobuf message:
 *
 *   message PublicKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * We parse/verify:
 *   - Field 1 is (tag=1, wire type=varint).
 *   - Field 2 is (tag=2, wire type=length-delimited).
 *   - No extra fields remain.
 *   - KeyType is one of {0..3} for RSA, Ed25519, Secp256k1, ECDSA (per the spec).
 *   - Varints are minimally encoded (the `unsigned_varint_decode` function should enforce canonical
 * form).
 *   - On success, sets *out_key_type and the pointer/length for the actual key bytes in
 * *out_key_data, *out_key_data_len.
 *
 * Returns 0 on success, < 0 on parse error.
 */
static int parse_public_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type,
                                  const uint8_t **out_key_data, size_t *out_key_data_len)
{
    if (!buf || !out_key_type || !out_key_data || !out_key_data_len)
    {
        return -1;
    }
    if (len == 0)
    {
        return -1;
    }

    unsigned_varint_err_t err;
    size_t offset = 0;

    /* Parse field #1 header: must be 0x08 (wire type=varint, field=1). */
    uint64_t field1_header;
    size_t field1_header_size;
    err = unsigned_varint_decode(buf + offset, len - offset, &field1_header, &field1_header_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    // wire type for "varint" + tag=1 => (1 << 3) + 0 => 0x08
    if (field1_header != 0x08)
    {
        return -1;
    }
    offset += field1_header_size;

    /* Parse KeyType (varint). */
    uint64_t key_type;
    size_t key_type_size;
    err = unsigned_varint_decode(buf + offset, len - offset, &key_type, &key_type_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    offset += key_type_size;

    // Check that key_type is in {0,1,2,3} for RSA=0, Ed25519=1, Secp256k1=2, ECDSA=3
    if (key_type > 3)
    {
        // Not recognized, or not supported by the spec
        return -1;
    }

    /* Parse field #2 header: must be 0x12 (wire type=length-delimited, field=2). */
    uint64_t field2_header;
    size_t field2_header_size;
    err = unsigned_varint_decode(buf + offset, len - offset, &field2_header, &field2_header_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    // wire type for "length-delimited" + tag=2 => (2 << 3) + 2 => 0x12
    if (field2_header != 0x12)
    {
        return -1;
    }
    offset += field2_header_size;

    /* Parse the length varint for the Data field. */
    uint64_t data_len;
    size_t data_len_size;
    err = unsigned_varint_decode(buf + offset, len - offset, &data_len, &data_len_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    offset += data_len_size;

    // Ensure we have enough bytes for that length
    if (data_len > (len - offset))
    {
        return -1;
    }

    // Set the pointers/length for the actual key bytes
    *out_key_data = buf + offset;
    *out_key_data_len = (size_t)data_len;

    offset += data_len;

    // If any bytes remain, it's an error (we want exactly 2 fields).
    if (offset != len)
    {
        return -1;
    }

    // Success
    *out_key_type = key_type;
    return 0;
}

peer_id_error_t peer_id_create_from_public_key(const uint8_t *pubkey_buf, size_t pubkey_len,
                                               peer_id_t *pid)
{
    if (!pubkey_buf || !pid)
    {
        return PEER_ID_E_NULL_PTR;
    }

    // Initialize output structure
    pid->bytes = NULL;
    pid->size = 0;

    // 1) Parse/validate the incoming public key protobuf.
    uint64_t key_type;
    const uint8_t *key_data = NULL;
    size_t key_data_len = 0;
    int parse_result =
        parse_public_key_proto(pubkey_buf, pubkey_len, &key_type, &key_data, &key_data_len);
    if (parse_result < 0)
    {
        // Parsing or validation failed
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    // 2) Determine the hash function to use based on the *entire* public key protobuf length.
    //    (The spec states we decide identity vs. sha2-256 based on the total serialized size).
    uint64_t hash_function_code;
    if (pubkey_len <= PEER_ID_IDENTITY_HASH_MAX_SIZE)
    {
        hash_function_code = MULTICODEC_IDENTITY;
    }
    else
    {
        hash_function_code = MULTICODEC_SHA2_256;
    }

    // 3) Calculate the maximum size of the multihash.
    size_t max_multihash_size;
    if (hash_function_code == MULTICODEC_IDENTITY)
    {
        // Identity multihash = varint(identity_code) + varint(length) + data
        size_t hash_code_size = unsigned_varint_size(hash_function_code);
        size_t digest_len_size = unsigned_varint_size(pubkey_len);
        max_multihash_size = hash_code_size + digest_len_size + pubkey_len;
    }
    else
    {
        // SHA256 multihash = varint(sha256_code) + varint(32) + 32-byte digest
        size_t hash_code_size = unsigned_varint_size(hash_function_code);
        size_t digest_len_size = unsigned_varint_size(32);
        max_multihash_size = hash_code_size + digest_len_size + 32;
    }

    // 4) Allocate memory for the multihash
    pid->bytes = (uint8_t *)malloc(max_multihash_size);
    if (!pid->bytes)
    {
        return PEER_ID_E_ALLOC_FAILED;
    }

    // 5) Compute the multihash over the *entire* protobuf (pubkey_buf)
    int result = multihash_encode(hash_function_code, pubkey_buf, pubkey_len, pid->bytes,
                                  max_multihash_size);
    if (result < 0)
    {
        free(pid->bytes);
        pid->bytes = NULL;
        pid->size = 0;

        // Map the multihash error code to a peer_id error code
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

peer_id_error_t peer_id_create_from_private_key(const uint8_t *privkey_buf, size_t privkey_len,
                                                peer_id_t *pid)
{
    if (!privkey_buf || !pid)
    {
        return PEER_ID_E_NULL_PTR;
    }

    // Initialize output structure.
    pid->bytes = NULL;
    pid->size = 0;

    // Step 1: Parse the private key protobuf.
    // The expected format is:
    //   field 1: key type (tag 1, varint, header = 0x08)
    //   field 2: key data (tag 2, length-delimited, header = 0x12)
    unsigned_varint_err_t err;
    size_t offset = 0;

    // Parse field #1 header.
    uint64_t field1_header;
    size_t field1_header_size;
    err = unsigned_varint_decode(privkey_buf + offset, privkey_len - offset, &field1_header,
                                 &field1_header_size);
    if (err != UNSIGNED_VARINT_OK || field1_header != 0x08)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }
    offset += field1_header_size;

    // Parse KeyType.
    uint64_t key_type;
    size_t key_type_size;
    err = unsigned_varint_decode(privkey_buf + offset, privkey_len - offset, &key_type,
                                 &key_type_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }
    offset += key_type_size;

    // Parse field #2 header.
    uint64_t field2_header;
    size_t field2_header_size;
    err = unsigned_varint_decode(privkey_buf + offset, privkey_len - offset, &field2_header,
                                 &field2_header_size);
    if (err != UNSIGNED_VARINT_OK || field2_header != 0x12)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }
    offset += field2_header_size;

    // Parse the length of the key data.
    uint64_t data_len;
    size_t data_len_size;
    err = unsigned_varint_decode(privkey_buf + offset, privkey_len - offset, &data_len,
                                 &data_len_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }
    offset += data_len_size;
    if (data_len > (privkey_len - offset))
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    const uint8_t *key_data = privkey_buf + offset;
    size_t key_data_len = (size_t)data_len;
    offset += key_data_len;

    // Ensure there are no extra bytes.
    if (offset != privkey_len)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    // Step 2: Derive the public key from the private key data using a dummy switch.
    uint8_t *pubkey_buf = NULL;
    size_t pubkey_len = 0;
    peer_id_error_t ret;

    switch (key_type)
    {
        case 0: // RSA
            ret = peer_id_create_from_private_key_rsa(key_data, key_data_len, &pubkey_buf,
                                                      &pubkey_len);
            break;
        case 1: // Ed25519
            ret = peer_id_create_from_private_key_ed25519(key_data, key_data_len, &pubkey_buf,
                                                          &pubkey_len);
            break;
        case 2: // Secp256k1
            ret = peer_id_create_from_private_key_secp256k1(key_data, key_data_len, &pubkey_buf,
                                                            &pubkey_len);
            break;
        case 3: // ECDSA
            ret = peer_id_create_from_private_key_ecdsa(key_data, key_data_len, &pubkey_buf,
                                                        &pubkey_len);
            break;
        default:
            return PEER_ID_E_UNSUPPORTED_KEY;
    }

    if (ret != PEER_ID_SUCCESS)
    {
        return ret;
    }

    // Step 3: Use the serialized public key to create the peer ID.
    ret = peer_id_create_from_public_key(pubkey_buf, pubkey_len, pid);

    // Free the temporary public key buffer if allocated.
    free(pubkey_buf);

    return ret;
}

peer_id_error_t peer_id_create_from_string(const char *str, peer_id_t *pid)
{
    if (!str || !pid)
    {
        return PEER_ID_E_NULL_PTR;
    }

    // Initialize output structure
    pid->bytes = NULL;
    pid->size = 0;

    // Check if it's a legacy base58btc multihash (starts with "Qm" or "1")
    if (starts_with(str, "Qm") || starts_with(str, "1"))
    {
        // Legacy base58btc multihash format

        // For legacy format, we need to add the BASE58_BTC_CHARACTER multibase prefix for base58btc
        // since our multibase_decode function expects a multibase prefixed string
        size_t input_len = strlen(str);
        char *prefixed_str = (char *)malloc(input_len + 2); // +1 for prefix, +1 for null terminator
        if (!prefixed_str)
        {
            return PEER_ID_E_ALLOC_FAILED;
        }

        prefixed_str[0] = BASE58_BTC_CHARACTER;
        strcpy(prefixed_str + 1, str);

        // Decode the base58btc string
        size_t max_decoded_size = input_len; // Base58 decoding produces a smaller output
        uint8_t *decoded = (uint8_t *)malloc(max_decoded_size);
        if (!decoded)
        {
            free(prefixed_str);
            return PEER_ID_E_ALLOC_FAILED;
        }

        int result =
            multibase_decode(MULTIBASE_BASE58_BTC, prefixed_str, decoded, max_decoded_size);
        free(prefixed_str); // Free the temporary prefixed string

        if (result < 0)
        {
            free(decoded);
            return PEER_ID_E_ENCODING_FAILED;
        }

        // Extract the digest length from the multihash to allocate proper buffer size
        size_t digest_len;
        if (extract_multihash_digest_length(decoded, result, &digest_len) < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Allocate a buffer of the exact size needed for the digest
        uint8_t *digest = (uint8_t *)malloc(digest_len);
        if (!digest)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        // Validate that the decoded data is a valid multihash
        uint64_t hash_func_code;
        size_t actual_digest_len = digest_len;

        int mh_result =
            multihash_decode(decoded, result, &hash_func_code, digest, &actual_digest_len);

        // Free the digest buffer as we only needed it for validation
        free(digest);

        if (mh_result < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Allocate memory for the peer ID and copy the decoded multihash
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
        // Check if it's a multibase encoded CIDv1
        multibase_t base = multibase_from_prefix(str[0]);
        if (base == (multibase_t)-1)
        {
            return PEER_ID_E_INVALID_STRING;
        }

        // Decode the multibase-encoded string
        size_t input_len = strlen(str);
        size_t max_decoded_size = input_len; // Multibase decoding produces a smaller output
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

        // Check if the decoded data is a valid CIDv1
        if (result < 2 || decoded[0] != MULTICODEC_CIDV1)
        { // CIDv1 starts with MULTICODEC_CIDV1
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Extract the multicodec
        uint64_t multicodec_code;
        size_t codec_size;
        unsigned_varint_err_t varint_result =
            unsigned_varint_decode(decoded + 1, result - 1, &multicodec_code, &codec_size);
        if (varint_result != UNSIGNED_VARINT_OK || multicodec_code != MULTICODEC_LIBP2P_KEY)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Extract the multihash
        size_t multihash_offset = 1 + codec_size;
        if (multihash_offset >= result)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Extract the digest length from the multihash to allocate proper buffer size
        size_t digest_len;
        if (extract_multihash_digest_length(decoded + multihash_offset, result - multihash_offset,
                                            &digest_len) < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Allocate a buffer of the exact size needed for the digest
        uint8_t *digest = (uint8_t *)malloc(digest_len);
        if (!digest)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        // Validate that the extracted bytes form a valid multihash
        uint64_t hash_func_code;
        size_t actual_digest_len = digest_len;

        int mh_result = multihash_decode(decoded + multihash_offset, result - multihash_offset,
                                         &hash_func_code, digest, &actual_digest_len);

        // Free the digest buffer as we only needed it for validation
        free(digest);

        if (mh_result < 0)
        {
            free(decoded);
            return PEER_ID_E_INVALID_STRING;
        }

        // Allocate memory for the peer ID and copy the extracted multihash
        pid->bytes = (uint8_t *)malloc(result - multihash_offset);
        if (!pid->bytes)
        {
            free(decoded);
            return PEER_ID_E_ALLOC_FAILED;
        }

        memcpy(pid->bytes, decoded + multihash_offset, result - multihash_offset);
        pid->size = result - multihash_offset;

        free(decoded);
        return PEER_ID_SUCCESS;
    }
    else
    {
        return PEER_ID_E_INVALID_STRING;
    }
}

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
        // Encode to base58btc with multibase prefix
        int result = multibase_encode(MULTIBASE_BASE58_BTC, pid->bytes, pid->size, out, out_size);
        if (result < 0)
        {
            return PEER_ID_E_ENCODING_FAILED;
        }

        // Remove the multibase prefix (assuming it's 1 character)
        if (result > 1 && out[0] == BASE58_BTC_CHARACTER)
        {
            memmove(out, out + 1, result);
            out[result - 1] = '\0'; // Ensure null termination
            return result - 1;
        }

        return result;
    }
    else if (format == PEER_ID_FMT_MULTIBASE_CIDv1)
    {
        // Convert to CIDv1 multibase encoded with multicodec = libp2p-key

        // Calculate the size of the CID: 1 byte for version + varint for multicodec + multihash
        size_t varint_size = unsigned_varint_size(MULTICODEC_LIBP2P_KEY);
        size_t cid_size = 1 + varint_size + pid->size;

        // Create a temporary buffer for the CID
        uint8_t *cid = (uint8_t *)malloc(cid_size);
        if (!cid)
        {
            return PEER_ID_E_ALLOC_FAILED;
        }

        // Set CIDv1 version
        cid[0] = MULTICODEC_CIDV1;

        // Encode the multicodec
        size_t written;
        unsigned_varint_err_t varint_result =
            unsigned_varint_encode(MULTICODEC_LIBP2P_KEY, cid + 1, varint_size, &written);
        if (varint_result != UNSIGNED_VARINT_OK)
        {
            free(cid);
            return PEER_ID_E_ENCODING_FAILED;
        }

        // Copy the multihash
        memcpy(cid + 1 + written, pid->bytes, pid->size);

        // Encode the CID in base32 (default for CIDv1)
        int result =
            multibase_encode(MULTIBASE_BASE32, cid, 1 + written + pid->size, out, out_size);

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

int peer_id_equals(const peer_id_t *a, const peer_id_t *b)
{
    if (!a || !b || !a->bytes || !b->bytes)
    {
        return -1; // Invalid input
    }

    if (a->size != b->size)
    {
        return 0; // Different sizes, cannot be equal
    }

    return memcmp(a->bytes, b->bytes, a->size) == 0 ? 1 : 0;
}

void peer_id_destroy(peer_id_t *pid)
{
    if (pid && pid->bytes)
    {
        free(pid->bytes);
        pid->bytes = NULL;
        pid->size = 0;
    }
}