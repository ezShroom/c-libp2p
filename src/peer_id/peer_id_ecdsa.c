#include <stdlib.h>

#include "../../lib/libtomcrypt/src/headers/tomcrypt.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"

#define PEER_ID_ECDSA_KEY_TYPE 3

peer_id_error_t peer_id_create_from_private_key_ecdsa(const uint8_t *key_data,
                                                      size_t key_data_len,
                                                      uint8_t **pubkey_buf,
                                                      size_t *pubkey_len)
{
    if (!key_data || !pubkey_buf || !pubkey_len)
    {
        return PEER_ID_E_NULL_PTR;
    }

    if (ltc_mp.name == NULL)
    {
#if defined(LTM_DESC)
        ltc_mp = ltm_desc;
#elif defined(TFM_DESC)
        ltc_mp = tfm_desc;
#elif defined(GMP_DESC)
        ltc_mp = gmp_desc;
#else
        return PEER_ID_E_CRYPTO_FAILED;
#endif

        if (ltc_mp.name == NULL)
        {
            return PEER_ID_E_CRYPTO_FAILED;
        }
    }

#ifdef LTC_MECC
    ecc_key ecdsa_key;
    int err = ecc_import_openssl(key_data, key_data_len, &ecdsa_key);
    if (err != CRYPT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    /* Use a minimal initial allocation and let ecc_export_openssl update der_len */
    unsigned long der_len = 1;
    uint8_t *der_buf = malloc(der_len);
    if (!der_buf)
    {
        ecc_free(&ecdsa_key);
        return PEER_ID_E_ALLOC_FAILED;
    }

    err = ecc_export_openssl(der_buf, &der_len, PK_PUBLIC | PK_CURVEOID, &ecdsa_key);
    if (err == CRYPT_BUFFER_OVERFLOW)
    {
        uint8_t *new_der_buf = realloc(der_buf, der_len);
        if (!new_der_buf)
        {
            free(der_buf);
            ecc_free(&ecdsa_key);
            return PEER_ID_E_ALLOC_FAILED;
        }
        der_buf = new_der_buf;
        err = ecc_export_openssl(der_buf, &der_len, PK_PUBLIC | PK_CURVEOID, &ecdsa_key);
    }
    if (err != CRYPT_OK)
    {
        free(der_buf);
        ecc_free(&ecdsa_key);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    peer_id_error_t ret = peer_id_build_public_key_protobuf(PEER_ID_ECDSA_KEY_TYPE,
                                                            der_buf, der_len,
                                                            pubkey_buf, pubkey_len);
    free(der_buf);
    ecc_free(&ecdsa_key);
    return ret;
#else
    return PEER_ID_E_CRYPTO_FAILED;
#endif
}