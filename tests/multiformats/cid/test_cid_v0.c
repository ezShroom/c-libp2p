#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/cid/cid_v0.h"
#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec_codes.h"

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

#define CIDV0_BINARY_SIZE 34
#define CIDV0_STRING_LEN 46

typedef struct
{
    const char *description;
    uint8_t digest[CIDV0_HASH_SIZE];
} cid_v0_test_vector;

int main(void)
{
    int failures = 0;
    int ret;
    char test_name[128];
    char str[64];
    uint8_t bin[CIDV0_BINARY_SIZE];
    cid_v0_test_vector tests[] = {
        {"Incremental bytes", {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}},
        {"All zeros", {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
        {"All 0xFF", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < num_tests; i++)
    {
        cid_v0_t cid, cid_from_bytes, cid_from_str;
        sprintf(test_name, "cid_v0_init(%s)", tests[i].description);
        ret = cid_v0_init(&cid, tests[i].digest, CIDV0_HASH_SIZE);
        if (ret != CIDV0_SUCCESS)
        {
            char details[256];
            sprintf(details, "cid_v0_init returned error code %d", ret);
            print_standard(test_name, details, 0);
            failures++;
            continue;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v0_to_bytes(%s)", tests[i].description);
        ret = cid_v0_to_bytes(&cid, bin, sizeof(bin));
        if (ret != CIDV0_BINARY_SIZE)
        {
            char details[256];
            sprintf(details, "Expected %d bytes, got %d", CIDV0_BINARY_SIZE, ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (bin[0] != MULTICODEC_SHA2_256 || bin[1] != 0x20 || memcmp(bin + 2, tests[i].digest, CIDV0_HASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Binary format mismatch for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v0_from_bytes(%s)", tests[i].description);
        ret = cid_v0_from_bytes(&cid_from_bytes, bin, sizeof(bin));
        if (ret != CIDV0_BINARY_SIZE)
        {
            char details[256];
            sprintf(details, "Expected %d bytes consumed, got %d", CIDV0_BINARY_SIZE, ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (memcmp(cid.hash, cid_from_bytes.hash, CIDV0_HASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Decoded digest does not match original for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v0_to_string(%s)", tests[i].description);
        ret = cid_v0_to_string(&cid, str, sizeof(str));
        if (ret != CIDV0_STRING_LEN)
        {
            char details[256];
            sprintf(details, "Expected %d characters, got %d", CIDV0_STRING_LEN, ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (str[0] != 'Q' || str[1] != 'm')
        {
            char details[256];
            sprintf(details, "String does not start with \"Qm\" for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v0_from_string(%s)", tests[i].description);
        ret = cid_v0_from_string(&cid_from_str, str);
        if (ret != CIDV0_STRING_LEN)
        {
            char details[256];
            sprintf(details, "Expected %d characters consumed, got %d", CIDV0_STRING_LEN, ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (memcmp(cid.hash, cid_from_str.hash, CIDV0_HASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Decoded digest from string does not match original for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v0_init(NULL, valid_digest, %d)", CIDV0_HASH_SIZE);
    {
        uint8_t valid_digest[CIDV0_HASH_SIZE] = {0};
        ret = cid_v0_init(NULL, valid_digest, CIDV0_HASH_SIZE);
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v0_init(valid_cid, valid_digest, wrong_length)");
    {
        cid_v0_t dummy;
        uint8_t valid_digest[16] = {0};
        ret = cid_v0_init(&dummy, valid_digest, 16);
        if (ret != CIDV0_ERROR_INVALID_DIGEST_LENGTH)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_INVALID_DIGEST_LENGTH, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v0_to_bytes(NULL, buf, size)");
    {
        uint8_t buf[CIDV0_BINARY_SIZE];
        ret = cid_v0_to_bytes(NULL, buf, sizeof(buf));
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_to_bytes(valid_cid, NULL, size)");
    {
        cid_v0_t dummy;
        uint8_t dummy_digest[CIDV0_HASH_SIZE] = {0};
        cid_v0_init(&dummy, dummy_digest, CIDV0_HASH_SIZE);
        ret = cid_v0_to_bytes(&dummy, NULL, CIDV0_BINARY_SIZE);
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_to_bytes(valid_cid, buf, too small)");
    {
        cid_v0_t dummy;
        uint8_t dummy_digest[CIDV0_HASH_SIZE] = {0};
        cid_v0_init(&dummy, dummy_digest, CIDV0_HASH_SIZE);
        uint8_t buf[CIDV0_BINARY_SIZE - 1];
        ret = cid_v0_to_bytes(&dummy, buf, sizeof(buf));
        if (ret != CIDV0_ERROR_BUFFER_TOO_SMALL)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_BUFFER_TOO_SMALL, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v0_from_bytes(NULL, bin, size)");
    {
        uint8_t local_bin[CIDV0_BINARY_SIZE] = {0};
        ret = cid_v0_from_bytes(NULL, local_bin, sizeof(local_bin));
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_from_bytes(valid_cid, NULL, size)");
    {
        cid_v0_t dummy;
        uint8_t local_bin[CIDV0_BINARY_SIZE] = {0};
        ret = cid_v0_from_bytes(&dummy, NULL, sizeof(local_bin));
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_from_bytes(valid_cid, bin, too small)");
    {
        cid_v0_t dummy;
        uint8_t local_bin[CIDV0_BINARY_SIZE] = {MULTICODEC_SHA2_256, 0x20};
        ret = cid_v0_from_bytes(&dummy, local_bin, CIDV0_BINARY_SIZE - 1);
        if (ret != CIDV0_ERROR_INVALID_DIGEST_LENGTH)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_INVALID_DIGEST_LENGTH, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v0_to_string(NULL, buf, size)");
    {
        char buf[64];
        ret = cid_v0_to_string(NULL, buf, sizeof(buf));
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_to_string(valid_cid, NULL, size)");
    {
        cid_v0_t dummy;
        uint8_t dummy_digest[CIDV0_HASH_SIZE] = {0};
        cid_v0_init(&dummy, dummy_digest, CIDV0_HASH_SIZE);
        ret = cid_v0_to_string(&dummy, NULL, 64);
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_to_string(valid_cid, buf, too small)");
    {
        cid_v0_t dummy;
        uint8_t dummy_digest[CIDV0_HASH_SIZE] = {0};
        cid_v0_init(&dummy, dummy_digest, CIDV0_HASH_SIZE);
        char buf[CIDV0_STRING_LEN - 1];
        ret = cid_v0_to_string(&dummy, buf, sizeof(buf));
        if (ret != CIDV0_ERROR_BUFFER_TOO_SMALL)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_BUFFER_TOO_SMALL, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v0_from_string(NULL, valid_str)");
    {
        char valid_str[CIDV0_STRING_LEN + 1] = "Qm01234567890123456789012345678901234567890123";
        ret = cid_v0_from_string(NULL, valid_str);
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_from_string(valid_cid, NULL)");
    {
        cid_v0_t dummy;
        ret = cid_v0_from_string(&dummy, NULL);
        if (ret != CIDV0_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_from_string(valid_cid, invalid_length_str)");
    {
        cid_v0_t dummy;
        char invalid_str[] = "abc123";
        ret = cid_v0_from_string(&dummy, invalid_str);
        if (ret != CIDV0_ERROR_DECODE_FAILURE)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_DECODE_FAILURE, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v0_from_string(valid_cid, invalid_prefix)");
    {
        cid_v0_t dummy;
        char invalid_str[CIDV0_STRING_LEN + 1] = "Xm0123456789012345678901234567890123456789012";
        invalid_str[CIDV0_STRING_LEN] = '\0';
        ret = cid_v0_from_string(&dummy, invalid_str);
        if (ret != CIDV0_ERROR_DECODE_FAILURE)
        {
            char details[256];
            sprintf(details, "Expected CIDV0_ERROR_DECODE_FAILURE, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    {
        const char *known_cid_str = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
        const uint8_t expected_digest[CIDV0_HASH_SIZE] = {0xc3, 0xc4, 0x73, 0x3e, 0xc8, 0xaf, 0xfd, 0x06, 0xcf, 0x9e, 0x9f,
                                                          0xf5, 0x0f, 0xfc, 0x6b, 0xcd, 0x2e, 0xc8, 0x5a, 0x61, 0x70, 0x00,
                                                          0x4b, 0xb7, 0x09, 0x66, 0x9c, 0x31, 0xde, 0x94, 0x39, 0x1a};
        cid_v0_t cid_from_known;
        int ret_local;

        sprintf(test_name, "cid_v0_from_string(known vector)");
        ret_local = cid_v0_from_string(&cid_from_known, known_cid_str);
        if (ret_local != CIDV0_STRING_LEN)
        {
            char details[256];
            sprintf(details, "Expected %d characters consumed, got %d", CIDV0_STRING_LEN, ret_local);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (memcmp(cid_from_known.hash, expected_digest, CIDV0_HASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Decoded digest does not match expected known vector");
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v0_to_string(known vector)");
        ret_local = cid_v0_to_string(&cid_from_known, str, sizeof(str));
        if (ret_local != CIDV0_STRING_LEN)
        {
            char details[256];
            sprintf(details, "Expected %d characters, got %d", CIDV0_STRING_LEN, ret_local);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (strcmp(str, known_cid_str) != 0)
        {
            char details[256];
            sprintf(details, "Encoded string does not match known vector");
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
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