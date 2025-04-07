#include <stdlib.h>

#include "../../lib/libtomcrypt/src/headers/tomcrypt.h"

#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"

#define PEER_ID_RSA_KEY_TYPE 0

peer_id_error_t peer_id_create_from_private_key_rsa(const uint8_t *key_data, size_t key_data_len,
                                                    uint8_t **pubkey_buf, size_t *pubkey_len)
{
    /* Validate inputs */
    if (!key_data || !pubkey_buf || !pubkey_len)
        return PEER_ID_E_NULL_PTR;

    /* Import the RSA private key (DER-encoded PKCS#1) */
    rsa_key key;
    int err = rsa_import(key_data, key_data_len, &key);
    if (err != CRYPT_OK)
        return PEER_ID_E_INVALID_PROTOBUF;

    /* Determine the required DER buffer size for the public key */
    int size_needed = rsa_get_size(&key);
    if (size_needed <= 0)
    {
        rsa_free(&key);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    unsigned long der_len = (unsigned long)size_needed;
    uint8_t *der_buf = malloc(der_len);
    if (!der_buf)
    {
        rsa_free(&key);
        return PEER_ID_E_ALLOC_FAILED;
    }

    /* Export the public key in DER (PKIX) format */
    err = rsa_export(der_buf, &der_len, PK_PUBLIC, &key);
    rsa_free(&key);
    if (err != CRYPT_OK)
    {
        free(der_buf);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    /* Build the PublicKey protobuf message using key type 0 for RSA */
    peer_id_error_t ret = peer_id_build_public_key_protobuf(PEER_ID_RSA_KEY_TYPE, der_buf, der_len,
                                                            pubkey_buf, pubkey_len);
    free(der_buf);
    return ret;
}