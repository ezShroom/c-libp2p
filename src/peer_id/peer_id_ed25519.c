#include <stdlib.h>

#include "../../lib/libtomcrypt/src/headers/tomcrypt.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_proto.h"
#include "peer_id/peer_id_ed25519.h"

peer_id_error_t peer_id_create_from_private_key_ed25519(const uint8_t *key_data,
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
    }
    if (ltc_mp.name == NULL)
    {
        return PEER_ID_E_CRYPTO_FAILED;
    }

#ifdef LTC_CURVE25519
    curve25519_key ed_key;
    int err = ed25519_import_raw(key_data, key_data_len, PK_PRIVATE, &ed_key);
    if (err != CRYPT_OK)
    {
        return PEER_ID_E_INVALID_PROTOBUF;
    }

    unsigned long der_len = 1;
    uint8_t *der_buf = malloc(der_len);
    if (!der_buf)
    {
        return PEER_ID_E_ALLOC_FAILED;
    }

    err = ed25519_export(der_buf, &der_len, PK_PUBLIC | PK_CURVEOID, &ed_key);
    if (err == CRYPT_BUFFER_OVERFLOW)
    {
        uint8_t *new_der_buf = realloc(der_buf, der_len);
        if (!new_der_buf)
        {
            free(der_buf);
            return PEER_ID_E_ALLOC_FAILED;
        }
        der_buf = new_der_buf;
        err = ed25519_export(der_buf, &der_len, PK_PUBLIC | PK_CURVEOID, &ed_key);
    }
    if (err != CRYPT_OK)
    {
        free(der_buf);
        return PEER_ID_E_CRYPTO_FAILED;
    }

    peer_id_error_t ret = peer_id_build_public_key_protobuf(PEER_ID_ED25519_KEY_TYPE,
                                                            der_buf,
                                                            der_len,
                                                            pubkey_buf,
                                                            pubkey_len);
    free(der_buf);

    return ret;
#else
    return PEER_ID_E_CRYPTO_FAILED;
#endif
}