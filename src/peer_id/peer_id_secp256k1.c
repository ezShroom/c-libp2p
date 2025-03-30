#include <stdlib.h>
#include <secp256k1.h>
#include "peer_id/peer_id.h"


peer_id_error_t peer_id_create_from_private_key_secp256k1(const uint8_t *key_data, size_t key_data_len,
                                                           uint8_t **pubkey_buf, size_t *pubkey_len)
{
    // Validate inputs.
    if (!key_data || !pubkey_buf || !pubkey_len) {
        return PEER_ID_E_NULL_PTR;
    }

    // For secp256k1, the secret key must be exactly 32 bytes.
    if (key_data_len != 32) {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    // Create a context for signing.
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        return PEER_ID_E_CRYPTO_FAILED;
    }

    // Verify that the provided secret key is valid.
    if (!secp256k1_ec_seckey_verify(ctx, key_data)) {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    // Derive the public key from the private key.
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key_data)) {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    // Allocate memory for the compressed public key (33 bytes).
    uint8_t *buf = (uint8_t *)malloc(33);
    if (!buf) {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_ALLOC_FAILED;
    }

    size_t len = 33;
    // Serialize the public key in compressed format.
    if (!secp256k1_ec_pubkey_serialize(ctx, buf, &len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        free(buf);
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    // Ensure that the output is 33 bytes.
    if (len != 33) {
        free(buf);
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    *pubkey_buf = buf;
    *pubkey_len = len;

    secp256k1_context_destroy(ctx);
    return PEER_ID_SUCCESS;
}