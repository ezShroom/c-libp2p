#include <string.h>
#include "multiformats/multihash/multihash.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "multiformats/multicodec/multicodec.h"
#include "../../../lib/sha3_pablotron/include/sha3.h"
#include "../../../lib/wjcryptlib/include/sha1.h"
#include "../../../lib/wjcryptlib/include/sha256.h"
#include "../../../lib/wjcryptlib/include/sha512.h"

#define SHA3_224_HASH_SIZE 28
#define SHA3_256_HASH_SIZE 32
#define SHA3_384_HASH_SIZE 48
#define SHA3_512_HASH_SIZE 64

/**
 * @brief Internal function to perform the actual hash.
 *
 * This function computes the digest for the provided data using the
 * specified hash function (indicated by the code parameter). It writes
 * the computed digest into digest_out and stores its length in digest_len.
 *
 * The multihash format requires a varint for the hash function code, a varint
 * for the digest length in bytes, and then the digest itself.
 *
 * This function returns MULTIHASH_SUCCESS on success, or an appropriate
 * error code if something goes wrong.
 */
static int compute_hash(
    uint64_t code,
    const uint8_t *data,
    size_t data_len,
    uint8_t *digest_out,
    size_t *digest_len)
{
    if (!data || !digest_out || !digest_len)
    {
        return MULTIHASH_ERR_NULL_POINTER;
    }

    switch (code)
    {
        case MULTICODEC_SHA1:
        {
            *digest_len = SHA1_HASH_SIZE; // SHA1 produces a 20-byte digest.
            SHA1_HASH hash;
            Sha1Calculate(data, (uint32_t)data_len, &hash);
            memcpy(digest_out, hash.bytes, SHA1_HASH_SIZE);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA2_256:
        {
            *digest_len = SHA256_HASH_SIZE; // SHA256 produces a 32-byte digest.
            SHA256_HASH hash;
            Sha256Calculate(data, (uint32_t)data_len, &hash);
            memcpy(digest_out, hash.bytes, SHA256_HASH_SIZE);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA2_512:
        {
            *digest_len = SHA512_HASH_SIZE; // SHA512 produces a 64-byte digest.
            SHA512_HASH hash;
            Sha512Calculate(data, (uint32_t)data_len, &hash);
            memcpy(digest_out, hash.bytes, SHA512_HASH_SIZE);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_224:
        {
            *digest_len = SHA3_224_HASH_SIZE; // SHA3-224 produces a 28-byte digest.
            sha3_224(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_256:
        {
            *digest_len = SHA3_256_HASH_SIZE; /* SHA3-256 produces a 32-byte digest. */
            sha3_256(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_384:
        {
            *digest_len = SHA3_384_HASH_SIZE; /* SHA3-384 produces a 48-byte digest. */
            sha3_384(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        case MULTICODEC_SHA3_512:
        {
            *digest_len = SHA3_512_HASH_SIZE; /* SHA3-512 produces a 64-byte digest. */
            sha3_512(data, data_len, digest_out);
            return MULTIHASH_SUCCESS;
        }
        default:
            return MULTIHASH_ERR_UNSUPPORTED_FUN;
    }
}

/**
 * @brief Encode a multihash.
 *
 * This function writes the varint-encoded hash function code,
 * the varint-encoded digest length, and then the digest itself
 * into the output buffer.
 */
int multihash_encode(
    uint64_t code,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_len)
{
    if (!data || !out)
    {
        return MULTIHASH_ERR_NULL_POINTER;
    }

    uint8_t digest_buf[512]; /* Temporary buffer for digest */
    size_t digest_len = 0;
    int hash_res = compute_hash(code, data, data_len, digest_buf, &digest_len);
    if (hash_res != MULTIHASH_SUCCESS)
    {
        return hash_res;
    }

    size_t written = 0;
    unsigned_varint_err_t err = unsigned_varint_encode(code, out, out_len, &written);
    if (err != UNSIGNED_VARINT_OK)
    {
        return err;
    }

    size_t written2 = 0;
    err = unsigned_varint_encode((uint64_t)digest_len, out + written, out_len - written, &written2);
    if (err != UNSIGNED_VARINT_OK)
    {
        return err;
    }

    size_t total = written + written2;
    if (total + digest_len > out_len)
    {
        return MULTIHASH_ERR_INVALID_INPUT;
    }

    memcpy(out + total, digest_buf, digest_len);
    total += digest_len;

    return (int)total;
}

/**
 * @brief Decode a multihash.
 *
 * This function decodes the varint-encoded function code and digest length,
 * then copies the digest into the provided buffer.
 */
int multihash_decode(
    const uint8_t *in,
    size_t in_len,
    uint64_t *code,
    uint8_t *digest,
    size_t *digest_len)
{
    if (!in || !code || !digest || !digest_len)
    {
        return MULTIHASH_ERR_NULL_POINTER;
    }

    uint64_t decoded_code = 0;
    size_t read1 = 0;
    unsigned_varint_err_t err = unsigned_varint_decode(in, in_len, &decoded_code, &read1);
    if (err != UNSIGNED_VARINT_OK)
    {
        return err;
    }

    uint64_t dlen = 0;
    size_t read2 = 0;
    err = unsigned_varint_decode(in + read1, in_len - read1, &dlen, &read2);
    if (err != UNSIGNED_VARINT_OK)
    {
        return err;
    }

    size_t offset = read1 + read2;
    if (offset + dlen > in_len)
    {
        return MULTIHASH_ERR_INVALID_INPUT;
    }
    if (dlen > *digest_len)
    {
        return MULTIHASH_ERR_DIGEST_TOO_LARGE;
    }

    memcpy(digest, in + offset, dlen);
    *digest_len = dlen;

    const char *codec_name = multicodec_name_from_code(decoded_code);
    if (!codec_name)
    {
        return MULTIHASH_ERR_UNSUPPORTED_FUN;
    }
    *code = decoded_code;

    return (int)(offset + dlen);
}