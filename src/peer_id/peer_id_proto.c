#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id_proto.h"

#define PUBKEY_TYPE_FIELD_TAG 0x08 /* (tag=1, wire type=varint) */
#define PUBKEY_DATA_FIELD_TAG 0x12 /* (tag=2, wire type=length-delimited) */

/**
 * @brief Check if a decoded varint used the minimal number of bytes.
 *
 * @param v The decoded varint value.
 * @param decoded_sz The number of bytes used in the decoded varint.
 * @return true if the encoding is minimal, false otherwise.
 */
static inline bool varint_is_minimal(uint64_t v, size_t decoded_sz)
{
    uint8_t tmp[10];
    size_t min_sz;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &min_sz) != UNSIGNED_VARINT_OK)
    {
        return false;
    }
    return min_sz == decoded_sz;
}

/**
 * @brief Parse a protobuf-encoded PublicKey message.
 *
 * The expected message format is:
 *
 *   message PublicKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * This function parses the message and extracts:
 *   - out_key_type: The key type (0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA).
 *   - out_key_data: Pointer into the buffer for the key data.
 *   - out_key_data_len: The length of the key data in bytes.
 *
 * @param buf              Pointer to the protobuf-encoded data.
 * @param len              Length of the data in bytes.
 * @param out_key_type     [out] Parsed key type.
 * @param out_key_data     [out] Pointer to the raw key data.
 * @param out_key_data_len [out] Length of the raw key data.
 *
 * @return 0 on success, a negative error code on failure.
 */
peer_id_error_t peer_id_build_public_key_protobuf(uint64_t key_type, const uint8_t *raw_key_data, size_t raw_key_len, uint8_t **out_buf,
                                                  size_t *out_size)
{
    if (!raw_key_data || !out_buf || !out_size)
    {
        return PEER_ID_E_NULL_PTR;
    }

    /* Enforce valid KeyType enum (0-3) */
    if (key_type > 3)
    {
        return PEER_ID_E_INVALID_RANGE;
    }

    /* Ensure raw_key_len fits in uint64_t without truncation */
    uint64_t raw_key_len_u64 = (uint64_t)raw_key_len;
    if ((size_t)raw_key_len_u64 != raw_key_len)
    {
        return PEER_ID_E_INVALID_RANGE;
    }

    /* Varint-encode the key type */
    uint8_t key_type_buf[10];
    size_t key_type_size;
    if (unsigned_varint_encode(key_type, key_type_buf, sizeof(key_type_buf), &key_type_size) != UNSIGNED_VARINT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    /* Varint-encode the length of the key data */
    uint8_t length_buf[10];
    size_t length_size;
    if (unsigned_varint_encode(raw_key_len_u64, length_buf, sizeof(length_buf), &length_size) != UNSIGNED_VARINT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    /* Prevent integer overflow: two tags + varint lengths */
    size_t header_size = 1 + key_type_size + 1 + length_size;
    if (raw_key_len > SIZE_MAX - header_size)
    {
        return PEER_ID_E_INVALID_RANGE;
    }

    size_t total = header_size + raw_key_len;
    uint8_t *buf = malloc(total);
    if (!buf)
    {
        return PEER_ID_E_ALLOC_FAILED;
    }

    size_t offset = 0;
    buf[offset++] = PUBKEY_TYPE_FIELD_TAG;
    memcpy(buf + offset, key_type_buf, key_type_size);
    offset += key_type_size;

    buf[offset++] = PUBKEY_DATA_FIELD_TAG;
    memcpy(buf + offset, length_buf, length_size);
    offset += length_size;

    memcpy(buf + offset, raw_key_data, raw_key_len);

    *out_buf = buf;
    *out_size = total;
    return PEER_ID_SUCCESS;
}

/**
 * @brief Parse a protobuf-encoded PublicKey message.
 *
 * The expected message format is:
 *
 *   message PublicKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * This function parses the message and extracts:
 *   - out_key_type: The key type (0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA).
 *   - out_key_data: Pointer into the buffer for the key data.
 *   - out_key_data_len: The length of the key data in bytes.
 *
 * @param buf              Pointer to the protobuf-encoded data.
 * @param len              Length of the data in bytes.
 * @param out_key_type     [out] Parsed key type.
 * @param out_key_data     [out] Pointer to the raw key data.
 * @param out_key_data_len [out] Length of the raw key data.
 *
 * @return 0 on success, a negative error code on failure.
 */
int parse_public_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data, size_t *out_key_data_len)
{
    if (!buf || !out_key_type || !out_key_data || !out_key_data_len || len == 0)
    {
        return -1;
    }

    unsigned_varint_err_t err;
    size_t offset = 0;

    /* field #1 header */
    uint64_t hdr1;
    size_t hdr1_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &hdr1, &hdr1_sz);
    if (err != UNSIGNED_VARINT_OK || hdr1 != PUBKEY_TYPE_FIELD_TAG || !varint_is_minimal(hdr1, hdr1_sz))
    {
        return -1;
    }
    offset += hdr1_sz;

    /* KeyType */
    uint64_t key_type;
    size_t key_type_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &key_type, &key_type_sz);
    if (err != UNSIGNED_VARINT_OK || !varint_is_minimal(key_type, key_type_sz) || key_type > 3)
    {
        return -1;
    }
    offset += key_type_sz;

    /* field #2 header */
    uint64_t hdr2;
    size_t hdr2_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &hdr2, &hdr2_sz);
    if (err != UNSIGNED_VARINT_OK || hdr2 != PUBKEY_DATA_FIELD_TAG || !varint_is_minimal(hdr2, hdr2_sz))
    {
        return -1;
    }
    offset += hdr2_sz;

    /* data length */
    uint64_t data_len;
    size_t data_len_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &data_len, &data_len_sz);
    if (err != UNSIGNED_VARINT_OK || !varint_is_minimal(data_len, data_len_sz))
    {
        return -1;
    }
    offset += data_len_sz;

    /* Prevent overflow when converting and reading data */
    if (data_len > SIZE_MAX || data_len > len - offset)
    {
        return -1;
    }

    *out_key_data = buf + offset;
    *out_key_data_len = (size_t)data_len;
    offset += data_len;

    if (offset != len)
    {
        return -1;
    }

    *out_key_type = key_type;
    return 0;
}

/**
 * @brief Parse a protobuf-encoded PrivateKey.
 *
 * @param buf              Pointer to the protobuf-encoded data.
 * @param len              Length of the data in bytes.
 * @param out_key_type     [out] Parsed key type.
 * @param out_key_data     [out] Pointer to the raw key data.
 * @param out_key_data_len [out] Length of the raw key data.
 *
 * @return 0 on success, a negative error code on failure.
 */
int parse_private_key_proto(const uint8_t *buf, size_t len, uint64_t *out_key_type, const uint8_t **out_key_data, size_t *out_key_data_len)
{
    if (!buf || !out_key_type || !out_key_data || !out_key_data_len || len == 0)
    {
        return -1;
    }

    unsigned_varint_err_t err;
    size_t offset = 0;

    /* field #1 header */
    uint64_t hdr1;
    size_t hdr1_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &hdr1, &hdr1_sz);
    if (err != UNSIGNED_VARINT_OK || hdr1 != PUBKEY_TYPE_FIELD_TAG || !varint_is_minimal(hdr1, hdr1_sz))
    {
        return -1;
    }
    offset += hdr1_sz;

    /* KeyType */
    uint64_t key_type;
    size_t key_type_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &key_type, &key_type_sz);
    if (err != UNSIGNED_VARINT_OK || !varint_is_minimal(key_type, key_type_sz) || key_type > 3)
    {
        return -1;
    }
    offset += key_type_sz;

    /* field #2 header */
    uint64_t hdr2;
    size_t hdr2_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &hdr2, &hdr2_sz);
    if (err != UNSIGNED_VARINT_OK || hdr2 != PUBKEY_DATA_FIELD_TAG || !varint_is_minimal(hdr2, hdr2_sz))
    {
        return -1;
    }
    offset += hdr2_sz;

    /* data length */
    uint64_t data_len;
    size_t data_len_sz;
    err = unsigned_varint_decode(buf + offset, len - offset, &data_len, &data_len_sz);
    if (err != UNSIGNED_VARINT_OK || !varint_is_minimal(data_len, data_len_sz))
    {
        return -1;
    }
    offset += data_len_sz;

    /* Prevent overflow when converting and reading data */
    if (data_len > SIZE_MAX || data_len > len - offset)
    {
        return -1;
    }

    *out_key_data = buf + offset;
    *out_key_data_len = (size_t)data_len;
    offset += data_len;

    if (offset != len)
    {
        return -1;
    }

    *out_key_type = key_type;
    return 0;
}