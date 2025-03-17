#include <stddef.h>
#include <stdint.h>

#define BASE64_URL_PAD_CHARACTER 'U'
#define BASE64_URL_PAD_UNICODE   0x0055

int base64_url_pad_encode(const uint8_t* data, size_t data_len, char* out, size_t out_len)
{
    // TODO: Implement base64 url pad encoding
    return 0;
}

int base64_url_pad_decode(const char* in, uint8_t* out, size_t out_len)
{
    // TODO: Implement base64 url pad decoding
    return 0;
}