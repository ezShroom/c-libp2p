#include <stdlib.h>
#include <string.h>

#include "peer_id/peer_id_proto.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"

#define PUBKEY_TYPE_FIELD_TAG 0x08  // (tag=1, wire type=varint) ->  (1 << 3) + 0 = 0x08
#define PUBKEY_DATA_FIELD_TAG 0x12  // (tag=2, wire type=length-delimited) -> (2 << 3) + 2 = 0x12

peer_id_error_t peer_id_build_public_key_protobuf(uint64_t key_type,
                                                  const uint8_t *raw_key_data,
                                                  size_t raw_key_len,
                                                  uint8_t **out_buf,
                                                  size_t *out_size)
{
    if (!raw_key_data || !out_buf || !out_size)
    {
        return PEER_ID_E_NULL_PTR;
    }

    // 1) Varint-encode the key_type
    uint8_t key_type_buf[10]; 
    size_t key_type_size;
    if (unsigned_varint_encode(key_type, key_type_buf, sizeof(key_type_buf), &key_type_size)
        != UNSIGNED_VARINT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    // 2) Varint-encode the length of raw_key_data
    uint8_t length_buf[10];
    size_t length_size;
    if (unsigned_varint_encode(raw_key_len, length_buf, sizeof(length_buf), &length_size)
        != UNSIGNED_VARINT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    size_t total = 1 + key_type_size + 1 + length_size + raw_key_len;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
    {
        return PEER_ID_E_ALLOC_FAILED;
    }

    size_t offset = 0;
    buf[offset++] = PUBKEY_TYPE_FIELD_TAG; // field #1 tag
    memcpy(buf + offset, key_type_buf, key_type_size);
    offset += key_type_size;

    buf[offset++] = PUBKEY_DATA_FIELD_TAG; // field #2 tag
    memcpy(buf + offset, length_buf, length_size);
    offset += length_size;

    memcpy(buf + offset, raw_key_data, raw_key_len);

    *out_buf  = buf;
    *out_size = total;

    return PEER_ID_SUCCESS;
}

/*
 * Minimal parser for a PublicKey protobuf message:
 *
 *   message PublicKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * Returns 0 on success, < 0 on parse error.
 */
int parse_public_key_proto(const uint8_t *buf,
                           size_t len,
                           uint64_t *out_key_type,
                           const uint8_t **out_key_data,
                           size_t *out_key_data_len)
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
        // Not recognized or not supported
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
    *out_key_data     = buf + offset;
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

/*
 * Minimal parser for a PrivateKey protobuf message:
 *
 *   message PrivateKey {
 *       required KeyType Type = 1;   // varint
 *       required bytes   Data = 2;   // length-delimited
 *   }
 *
 * Returns 0 on success, < 0 on parse error.
 */
int parse_private_key_proto(const uint8_t *buf,
                            size_t len,
                            uint64_t *out_key_type,
                            const uint8_t **out_key_data,
                            size_t *out_key_data_len)
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

    // Parse field #1 header (must be 0x08)
    uint64_t field1_header;
    size_t field1_header_size;
    err = unsigned_varint_decode(buf + offset, len - offset,
                                 &field1_header, &field1_header_size);
    if (err != UNSIGNED_VARINT_OK || field1_header != 0x08)
    {
        return -1;
    }
    offset += field1_header_size;

    // Parse KeyType
    uint64_t key_type;
    size_t key_type_size;
    err = unsigned_varint_decode(buf + offset, len - offset,
                                 &key_type, &key_type_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    offset += key_type_size;

    // Parse field #2 header (must be 0x12)
    uint64_t field2_header;
    size_t field2_header_size;
    err = unsigned_varint_decode(buf + offset, len - offset,
                                 &field2_header, &field2_header_size);
    if (err != UNSIGNED_VARINT_OK || field2_header != 0x12)
    {
        return -1;
    }
    offset += field2_header_size;

    // Parse the length of the key data
    uint64_t data_len;
    size_t data_len_size;
    err = unsigned_varint_decode(buf + offset, len - offset,
                                 &data_len, &data_len_size);
    if (err != UNSIGNED_VARINT_OK)
    {
        return -1;
    }
    offset += data_len_size;

    if (data_len > (len - offset))
    {
        return -1;
    }

    // Set pointers to the private-key data
    *out_key_data     = buf + offset;
    *out_key_data_len = (size_t)data_len;
    offset += data_len;

    // Ensure no extra bytes remain
    if (offset != len)
    {
        return -1;
    }

    *out_key_type = key_type;
    return 0;
}