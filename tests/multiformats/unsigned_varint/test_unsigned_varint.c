#include "multiformats/unsigned_varint/unsigned_varint.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#ifdef _MSC_VER
    sprintf_s(test_name, sizeof(test_name), "Encode/Decode value=%llu", (unsigned long long)value);
#else
    sprintf(test_name, "Encode/Decode value=%llu", (unsigned long long)value);
#endif

    uint8_t buffer[16];
    memset(buffer, 0, sizeof(buffer));

    size_t written = 0;
    unsigned_varint_err_t err = unsigned_varint_encode(value, buffer, sizeof(buffer), &written);
    if (err != UNSIGNED_VARINT_OK)
    {
        char details[256];
        memset(details, 0, sizeof(details));
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Encoding error for value=%llu, err=%d", (unsigned long long)value, (int)err);
#else
        sprintf(details, "Encoding error for value=%llu, err=%d", (unsigned long long)value, (int)err);
#endif
        print_standard(test_name, details, 0);
        return 0;
    }

    char encoded_hex[64];
    memset(encoded_hex, 0, sizeof(encoded_hex));
    for (size_t i = 0; i < written; i++)
    {
#ifdef _MSC_VER
        sprintf_s(encoded_hex + (i * 2), sizeof(encoded_hex) - (i * 2), "%02x", buffer[i]);
#else
        sprintf(encoded_hex + (i * 2), "%02x", buffer[i]);
#endif
    }

    int ok = 1;
    char details[256];
    memset(details, 0, sizeof(details));

    if (expected_hex != NULL && strcmp(encoded_hex, expected_hex) != 0)
    {
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Encoded hex mismatch: got %s, expected %s", encoded_hex, expected_hex);
#else
        sprintf(details, "Encoded hex mismatch: got %s, expected %s", encoded_hex, expected_hex);
#endif
        ok = 0;
    }

    uint64_t decoded_val = 0;
    size_t read = 0;
    err = unsigned_varint_decode(buffer, written, &decoded_val, &read);
    if (err != UNSIGNED_VARINT_OK)
    {
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Decoding error for value=%llu, err=%d", (unsigned long long)value, (int)err);
#else
        sprintf(details, "Decoding error for value=%llu, err=%d", (unsigned long long)value, (int)err);
#endif
        ok = 0;
    }
    else if (decoded_val != value || read != written)
    {
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Decoded value/byte count mismatch: got %llu (%zu bytes), expected %llu (%zu bytes)",
                  (unsigned long long)decoded_val, read, (unsigned long long)value, written);
#else
        sprintf(details, "Decoded value/byte count mismatch: got %llu (%zu bytes), expected %llu (%zu bytes)", (unsigned long long)decoded_val, read,
                (unsigned long long)value, written);
#endif
        ok = 0;
    }

    print_standard(test_name, details, ok);
    return ok;
}

static int test_decode_failure(const uint8_t *data, size_t data_len, unsigned_varint_err_t expected_err, const char *test_name)
{
    uint64_t decoded_val = 0;
    size_t read = 0;
    unsigned_varint_err_t err = unsigned_varint_decode(data, data_len, &decoded_val, &read);

    int passed = (err == expected_err);
    char details[256];
    memset(details, 0, sizeof(details));
    if (!passed)
    {
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Expected error %d but got %d", (int)expected_err, (int)err);
#else
        sprintf(details, "Expected error %d but got %d", (int)expected_err, (int)err);
#endif
    }

    print_standard(test_name, details, passed);
    return passed;
}

static int test_encode_failure(uint64_t value, unsigned_varint_err_t expected_err, const char *test_name)
{
    uint8_t buffer[16];
    memset(buffer, 0, sizeof(buffer));
    size_t written = 0;
    unsigned_varint_err_t err = unsigned_varint_encode(value, buffer, sizeof(buffer), &written);

    int passed = (err == expected_err);
    char details[256];
    memset(details, 0, sizeof(details));
    if (!passed)
    {
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Expected error %d for value %llu, but got %d", (int)expected_err, (unsigned long long)value, (int)err);
#else
        sprintf(details, "Expected error %d for value %llu, but got %d", (int)expected_err, (unsigned long long)value, (int)err);
#endif
    }

    print_standard(test_name, details, passed);
    return passed;
}

static int test_unsigned_varint_size(uint64_t value, size_t expected_size)
{
    char test_name[128];
#ifdef _MSC_VER
    sprintf_s(test_name, sizeof(test_name), "unsigned_varint_size for value=%llu", (unsigned long long)value);
#else
    sprintf(test_name, "unsigned_varint_size for value=%llu", (unsigned long long)value);
#endif

    size_t size = unsigned_varint_size(value);
    int passed = (size == expected_size);

    char details[256];
    memset(details, 0, sizeof(details));
    if (!passed)
    {
#ifdef _MSC_VER
        sprintf_s(details, sizeof(details), "Expected size %zu but got %zu", expected_size, size);
#else
        sprintf(details, "Expected size %zu but got %zu", expected_size, size);
#endif
    }

    print_standard(test_name, details, passed);
    return passed;
}

static int test_null_parameters(void)
{
    int ok = 1;

    {
        const char *test_name = "Encode with NULL 'out'";
        size_t written = 0;
        unsigned_varint_err_t err = unsigned_varint_encode(100ULL, NULL, 10, &written);

        char details[256];
        memset(details, 0, sizeof(details));
        int passed = (err == UNSIGNED_VARINT_ERR_NULL_PTR);
        if (!passed)
        {
#ifdef _MSC_VER
            sprintf_s(details, sizeof(details), "Expected NULL_PTR, got %d", (int)err);
#else
            sprintf(details, "Expected NULL_PTR, got %d", (int)err);
#endif
        }
        print_standard(test_name, details, passed);
        if (!passed)
            ok = 0;
    }

    {
        const char *test_name = "Encode with NULL 'written'";
        uint8_t buffer[4];
        unsigned_varint_err_t err = unsigned_varint_encode(100ULL, buffer, sizeof(buffer), NULL);

        char details[256];
        memset(details, 0, sizeof(details));
        int passed = (err == UNSIGNED_VARINT_ERR_NULL_PTR);
        if (!passed)
        {
#ifdef _MSC_VER
            sprintf_s(details, sizeof(details), "Expected NULL_PTR, got %d", (int)err);
#else
            sprintf(details, "Expected NULL_PTR, got %d", (int)err);
#endif
        }
        print_standard(test_name, details, passed);
        if (!passed)
            ok = 0;
    }

    {
        const char *test_name = "Decode with NULL 'in'";
        uint64_t val = 0;
        size_t read = 0;
        unsigned_varint_err_t err = unsigned_varint_decode(NULL, 5, &val, &read);

        char details[256];
        memset(details, 0, sizeof(details));
        int passed = (err == UNSIGNED_VARINT_ERR_NULL_PTR);
        if (!passed)
        {
#ifdef _MSC_VER
            sprintf_s(details, sizeof(details), "Expected NULL_PTR, got %d", (int)err);
#else
            sprintf(details, "Expected NULL_PTR, got %d", (int)err);
#endif
        }
        print_standard(test_name, details, passed);
        if (!passed)
            ok = 0;
    }

    {
        const char *test_name = "Decode with NULL 'value'";
        uint8_t data[] = {0x01};
        size_t read = 0;
        unsigned_varint_err_t err = unsigned_varint_decode(data, 1, NULL, &read);

        char details[256];
        memset(details, 0, sizeof(details));
        int passed = (err == UNSIGNED_VARINT_ERR_NULL_PTR);
        if (!passed)
        {
#ifdef _MSC_VER
            sprintf_s(details, sizeof(details), "Expected NULL_PTR, got %d", (int)err);
#else
            sprintf(details, "Expected NULL_PTR, got %d", (int)err);
#endif
        }
        print_standard(test_name, details, passed);
        if (!passed)
            ok = 0;
    }

    {
        const char *test_name = "Decode with NULL 'read'";
        uint8_t data[] = {0x01};
        uint64_t val = 0;
        unsigned_varint_err_t err = unsigned_varint_decode(data, 1, &val, NULL);

        char details[256];
        memset(details, 0, sizeof(details));
        int passed = (err == UNSIGNED_VARINT_ERR_NULL_PTR);
        if (!passed)
        {
#ifdef _MSC_VER
            sprintf_s(details, sizeof(details), "Expected NULL_PTR, got %d", (int)err);
#else
            sprintf(details, "Expected NULL_PTR, got %d", (int)err);
#endif
        }
        print_standard(test_name, details, passed);
        if (!passed)
            ok = 0;
    }

    return ok;
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
    failures += test_encode_decode(268435455ULL, "ffffff7f") ? 0 : 1;
    failures += test_encode_decode(268435456ULL, "8080808001") ? 0 : 1;
    failures += test_encode_decode(34359738368ULL, "808080808001") ? 0 : 1;
    failures += test_encode_decode(1099511627776ULL, "808080808020") ? 0 : 1;
    failures += test_encode_decode(281474976710656ULL, "80808080808040") ? 0 : 1;

    {
        uint8_t non_minimal_for_1[] = {0x81, 0x00};
        failures +=
            test_decode_failure(non_minimal_for_1, sizeof(non_minimal_for_1), UNSIGNED_VARINT_ERR_NOT_MINIMAL, "Non-minimal encoding for 1") ? 0 : 1;
    }

    {
        uint8_t ten_bytes[] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
        failures += test_decode_failure(ten_bytes, sizeof(ten_bytes), UNSIGNED_VARINT_ERR_TOO_LONG, "10-byte sequence") ? 0 : 1;
    }

    {
        uint8_t truncated[] = {0x80};
        failures += test_decode_failure(truncated, sizeof(truncated), UNSIGNED_VARINT_ERR_TOO_LONG, "Truncated single 0x80") ? 0 : 1;
    }
    {
        uint8_t truncated_larger[] = {0xFF};
        failures += test_decode_failure(truncated_larger, sizeof(truncated_larger), UNSIGNED_VARINT_ERR_TOO_LONG, "Truncated single 0xFF") ? 0 : 1;
    }

    failures += test_encode_failure(0xFFFFFFFFFFFFFFFFULL, UNSIGNED_VARINT_ERR_VALUE_OVERFLOW, "Encoding >2^63-1") ? 0 : 1;
    failures += test_encode_failure(0x8000000000000000ULL, UNSIGNED_VARINT_ERR_VALUE_OVERFLOW, "Encoding 2^63") ? 0 : 1;

    {
        const uint8_t empty[1] = {};
        failures += test_decode_failure(empty, 0, UNSIGNED_VARINT_ERR_EMPTY_INPUT, "Empty input decode") ? 0 : 1;
    }

    {
        uint8_t varint_2_63[10] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
        failures += test_decode_failure(varint_2_63, sizeof(varint_2_63), UNSIGNED_VARINT_ERR_VALUE_OVERFLOW, "Decode 2^63") ? 0 : 1;
    }

    failures += test_unsigned_varint_size(0ULL, 1) ? 0 : 1;
    failures += test_unsigned_varint_size(1ULL, 1) ? 0 : 1;
    failures += test_unsigned_varint_size(127ULL, 1) ? 0 : 1;
    failures += test_unsigned_varint_size(128ULL, 2) ? 0 : 1;
    failures += test_unsigned_varint_size(255ULL, 2) ? 0 : 1;
    failures += test_unsigned_varint_size(300ULL, 2) ? 0 : 1;
    failures += test_unsigned_varint_size(16383ULL, 2) ? 0 : 1;
    failures += test_unsigned_varint_size(16384ULL, 3) ? 0 : 1;
    failures += test_unsigned_varint_size(0x7FFFFFFFFFFFFFFFULL, 9) ? 0 : 1;

    if (!test_null_parameters())
    {
        ++failures;
    }

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