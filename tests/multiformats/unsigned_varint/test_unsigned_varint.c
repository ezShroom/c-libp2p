#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/unsigned_varint/unsigned_varint.h"

static void print_standard(const char* test_name, const char* details, int passed)
{
    if (passed) {
        printf("TEST: %-50s | PASS\n", test_name);
    } else {
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
    }
}

static int test_encode_decode(uint64_t value, const char *expected_hex)
{
    char test_name[128];
    sprintf(test_name, "Encode/Decode value=%llu", (unsigned long long)value);

    uint8_t buffer[16];
    memset(buffer, 0, sizeof(buffer));

    size_t written = 0;
    mf_varint_err_t err = mf_uvarint_encode(value, buffer, sizeof(buffer), &written);
    if (err != MF_VARINT_OK) {
        char details[256];
        sprintf(details, "Encoding error for value=%llu, err=%d", (unsigned long long)value, (int)err);
        print_standard(test_name, details, 0);
        return 0;
    }

    char encoded_hex[64] = {0};
    for (size_t i = 0; i < written; i++) {
        sprintf(encoded_hex + (i * 2), "%02x", buffer[i]);
    }

    int ok = 1;
    char details[256] = {0};

    if (expected_hex != NULL && strcmp(encoded_hex, expected_hex) != 0) {
        sprintf(details, "Encoded hex mismatch: got %s, expected %s", encoded_hex, expected_hex);
        ok = 0;
    }

    uint64_t decoded_val = 0;
    size_t read = 0;
    err = mf_uvarint_decode(buffer, written, &decoded_val, &read);
    if (err != MF_VARINT_OK) {
        sprintf(details, "Decoding error for value=%llu, err=%d", (unsigned long long)value, (int)err);
        ok = 0;
    } else if (decoded_val != value || read != written) {
        sprintf(details, "Decoded value/byte count mismatch: got %llu (%zu bytes), expected %llu (%zu bytes)",
                (unsigned long long)decoded_val, read, (unsigned long long)value, written);
        ok = 0;
    }
    
    print_standard(test_name, details, ok);
    return ok;
}

static int test_decode_failure(const uint8_t *data, size_t data_len, mf_varint_err_t expected_err, const char* test_name)
{
    uint64_t decoded_val = 0;
    size_t read = 0;
    mf_varint_err_t err = mf_uvarint_decode(data, data_len, &decoded_val, &read);
    
    int passed = (err == expected_err);
    char details[256] = {0};
    if (!passed) {
        sprintf(details, "Expected error %d but got %d", (int)expected_err, (int)err);
    }
    print_standard(test_name, details, passed);
    return passed;
}

int main(void)
{
    test_encode_decode(1ULL, "01");
    test_encode_decode(127ULL, "7f");
    test_encode_decode(128ULL, "8001");
    test_encode_decode(255ULL, "ff01");
    test_encode_decode(300ULL, "ac02");
    test_encode_decode(16384ULL, "808001");
    test_encode_decode(0x7FFFFFFFFFFFFFFFULL, NULL);
    test_encode_decode(0ULL, "00");

    {
        uint8_t non_minimal_for_1[] = {0x81, 0x00};
        test_decode_failure(non_minimal_for_1, sizeof(non_minimal_for_1),
                            MF_VARINT_ERR_NOT_MINIMAL,
                            "Non-minimal encoding for 1 (0x81,0x00)");
    }

    {
        uint8_t ten_bytes[] = {
            0x80, 0x80, 0x80, 0x80, 0x80,
            0x80, 0x80, 0x80, 0x80, 0x00
        };
        test_decode_failure(ten_bytes, sizeof(ten_bytes),
                            MF_VARINT_ERR_TOO_LONG,
                            "10-byte overlong sequence");
    }

    {
        uint8_t truncated[] = {0x80};
        test_decode_failure(truncated, sizeof(truncated),
                            MF_VARINT_ERR_TOO_LONG,
                            "Truncated sequence (single 0x80)");
    }

    {
        uint8_t truncated_larger[] = {0xFF};
        test_decode_failure(truncated_larger, sizeof(truncated_larger),
                            MF_VARINT_ERR_TOO_LONG,
                            "Truncated sequence (single 0xFF)");
    }
    
    return 0;
}