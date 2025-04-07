#include <stdlib.h>

#include "peer_id/peer_id.h"

peer_id_error_t peer_id_create_from_private_key_rsa(const uint8_t *key_data,
                                                          size_t key_data_len, uint8_t **pubkey_buf,
                                                          size_t *pubkey_len)
{
    return PEER_ID_SUCCESS;
}