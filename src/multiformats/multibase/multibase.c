#include <stddef.h>
#include <stdint.h>

int multibase_encode(
    multibase_t base,
    const uint8_t *data,
    size_t data_len,
    char *out,
    size_t out_len)
{
    return MULTIBASE_SUCCESS;
}

int multibase_decode(
    const char *in,
    uint8_t *out,
    size_t out_len,
    multibase_t *out_base)
{
    return MULTIBASE_SUCCESS;
}