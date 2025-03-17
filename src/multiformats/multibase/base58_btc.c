#include <stddef.h>
#include <stdint.h>

#define BASE58_BTC_CHARACTER 'z'
#define BASE58_BTC_UNICODE   0x007A

int base58_btc_encode(const uint8_t* data, size_t data_len, char* out, size_t out_len)
{
    // TODO: Implement base58 btc encoding
    return 0;
}

int base58_btc_decode(const char* in, uint8_t* out, size_t out_len)
{
    // TODO: Implement base58 btc decoding
    return 0;
}