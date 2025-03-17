#include <stddef.h>
#include <stdint.h>

#define BASE64_URL_CHARACTER 'u'
#define BASE64_URL_UNICODE   0x0075

int base64_url_encode(const uint8_t* data, size_t data_len, char* out, size_t out_len)
{
    // TODO: Implement base64 url encoding
    return 0;
}

int base64_url_decode(const char* in, uint8_t* out, size_t out_len)
{
    // TODO: Implement base64 url decoding
    return 0;
}