#include <stdlib.h>
#include <string.h>

#include "../../lib/secp256k1/include/secp256k1.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_secp256k1.h"


peer_id_error_t peer_id_create_from_private_key_secp256k1(const uint8_t *key_data,
                                                          size_t key_data_len, uint8_t **pubkey_buf,
                                                          size_t *pubkey_len)
{
    if (!key_data || !pubkey_buf || !pubkey_len)
    {
        return PEER_ID_E_NULL_PTR;
    }

    if (key_data_len != 32)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx)
    {
        return PEER_ID_E_CRYPTO_FAILED;
    }

    if (!secp256k1_ec_seckey_verify(ctx, key_data))
    {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key_data))
    {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    uint8_t raw_pubkey[33];
    size_t len = sizeof(raw_pubkey);
    if (!secp256k1_ec_pubkey_serialize(ctx, raw_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED))
    {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }
    if (len != 33)
    {
        secp256k1_context_destroy(ctx);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    secp256k1_context_destroy(ctx);

    peer_id_error_t err = peer_id_build_public_key_protobuf(PEER_ID_SECP256K1_KEY_TYPE, raw_pubkey, len, pubkey_buf,
                                          pubkey_len);
    return err;
}