#include <stddef.h>
#include <stdint.h>

#define BASE32_UPPER_CHARACTER 'B'
#define BASE32_UPPER_UNICODE   0x0042

int base32_upper_encode(const uint8_t* data, size_t data_len, char* out, size_t out_len)
{
    // TODO: Implement base32 upper encoding
    return 0;
}

int base32_upper_decode(const char* in, uint8_t* out, size_t out_len)
{   
    // TODO: Implement base32 upper decoding
    return 0;
}