#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "multiformats/unsigned_varint/unsigned_varint.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
    {
        printf("TEST: %-50s | PASS\n", test_name);
    }
    else
    {
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
    if (err != MF_VARINT_OK)
    {
        char details[256];
        sprintf(details, "Encoding error for value=%llu, err=%d", (unsigned long long)value,
                (int)err);
        print_standard(test_name, details, 0);
        return 0;
    }

    char encoded_hex[64];
    memset(encoded_hex, 0, sizeof(encoded_hex));
    for (size_t i = 0; i < written; i++)
    {
        sprintf(encoded_hex + (i * 2), "%02x", buffer[i]);
    }

    int ok = 1;
    char details[256];
    memset(details, 0, sizeof(details));

    if (expected_hex != NULL && strcmp(encoded_hex, expected_hex) != 0)
    {
        sprintf(details, "Encoded hex mismatch: got %s, expected %s", encoded_hex, expected_hex);
        ok = 0;
    }

    uint64_t decoded_val = 0;
    size_t read = 0;
    err = mf_uvarint_decode(buffer, written, &decoded_val, &read);
    if (err != MF_VARINT_OK)
    {
        sprintf(details, "Decoding error for value=%llu, err=%d", (unsigned long long)value,
                (int)err);
        ok = 0;
    }
    else if (decoded_val != value || read != written)
    {
        sprintf(
            details,
            "Decoded value/byte count mismatch: got %llu (%zu bytes), expected %llu (%zu bytes)",
            (unsigned long long)decoded_val, read, (unsigned long long)value, written);
        ok = 0;
    }

    print_standard(test_name, details, ok);
    return ok;
}

static int test_decode_failure(const uint8_t *data, size_t data_len, mf_varint_err_t expected_err,
                               const char *test_name)
{
    uint64_t decoded_val = 0;
    size_t read = 0;
    mf_varint_err_t err = mf_uvarint_decode(data, data_len, &decoded_val, &read);
    int passed = (err == expected_err);
    char details[256];
    memset(details, 0, sizeof(details));
    if (!passed)
    {
        sprintf(details, "Expected error %d but got %d", (int)expected_err, (int)err);
    }
    print_standard(test_name, details, passed);
    return passed;
}

static int test_encode_failure(uint64_t value, mf_varint_err_t expected_err, const char *test_name)
{
    uint8_t buffer[16];
    memset(buffer, 0, sizeof(buffer));
    size_t written = 0;
    mf_varint_err_t err = mf_uvarint_encode(value, buffer, sizeof(buffer), &written);
    int passed = (err == expected_err);
    char details[256];
    memset(details, 0, sizeof(details));
    if (!passed)
    {
        sprintf(details, "Expected error %d for value %llu, but got %d", (int)expected_err,
                (unsigned long long)value, (int)err);
    }
    print_standard(test_name, details, passed);
    return passed;
}

int main(void)
{
    int failures = 0;

    failures += test_encode_decode(1ULL, "01") ? 0 : 1;
    failures += test_encode_decode(127ULL, "7f") ? 0 : 1;
    failures += test_encode_decode(128ULL, "8001") ? 0 : 1;
    failures += test_encode_decode(255ULL, "ff01") ? 0 : 1;
    failures += test_encode_decode(300ULL, "ac02") ? 0 : 1;
    failures += test_encode_decode(16384ULL, "808001") ? 0 : 1;
    failures += test_encode_decode(0x7FFFFFFFFFFFFFFFULL, NULL) ? 0 : 1;
    failures += test_encode_decode(0ULL, "00") ? 0 : 1;

    {
        uint8_t non_minimal_for_1[] = {0x81, 0x00};
        failures += test_decode_failure(non_minimal_for_1, sizeof(non_minimal_for_1),
                                        MF_VARINT_ERR_NOT_MINIMAL, "Non-minimal encoding for 1")
                        ? 0
                        : 1;
    }

    {
        uint8_t ten_bytes[] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
        failures += test_decode_failure(ten_bytes, sizeof(ten_bytes), MF_VARINT_ERR_TOO_LONG,
                                        "10-byte sequence")
                        ? 0
                        : 1;
    }

    {
        uint8_t truncated[] = {0x80};
        failures += test_decode_failure(truncated, sizeof(truncated), MF_VARINT_ERR_TOO_LONG,
                                        "Truncated single 0x80")
                        ? 0
                        : 1;
    }

    {
        uint8_t truncated_larger[] = {0xFF};
        failures += test_decode_failure(truncated_larger, sizeof(truncated_larger),
                                        MF_VARINT_ERR_TOO_LONG, "Truncated single 0xFF")
                        ? 0
                        : 1;
    }

    failures +=
        test_encode_failure(0xFFFFFFFFFFFFFFFFULL, MF_VARINT_ERR_VALUE_OVERFLOW, "Encoding >2^63-1")
            ? 0
            : 1;

    {
        uint8_t empty[1] = {};
        failures +=
            test_decode_failure(empty, 0, MF_VARINT_ERR_TOO_LONG, "Empty input decode") ? 0 : 1;
    }

    {
        uint8_t varint_2_63[10] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
        failures += test_decode_failure(varint_2_63, sizeof(varint_2_63),
                                        MF_VARINT_ERR_VALUE_OVERFLOW, "Decode 2^63")
                        ? 0
                        : 1;
    }

    failures +=
        test_encode_failure(0x8000000000000000ULL, MF_VARINT_ERR_VALUE_OVERFLOW, "Encoding 2^63")
            ? 0
            : 1;

    if (failures)
    {
        printf("\nSome tests failed. Total failures: %d\n", failures);
        return EXIT_FAILURE;
    }
    else
    {
        printf("\nAll tests passed!\n");
        return EXIT_SUCCESS;
    }
}
