#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/cid/cid_v1.h"
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

#define CIDV1_DIGEST_SIZE 32
#define CIDV1_MULTIHASH_SIZE (CIDV1_DIGEST_SIZE + 2)
#define CIDV1_BINARY_SIZE 36

#ifndef MULTICODEC_RAW
#define MULTICODEC_RAW 0x55
#endif

typedef struct
{
    const char *description;
    uint8_t digest[CIDV1_DIGEST_SIZE];
} cid_v1_test_vector;

int main(void)
{
    int failures = 0;
    int ret;
    char test_name[128];

    cid_v1_test_vector tests[] = {
        {"Incremental bytes",
         {0, 1, 2, 3, 4, 5, 6, 7,
          8, 9, 10, 11, 12, 13, 14, 15,
          16, 17, 18, 19, 20, 21, 22, 23,
          24, 25, 26, 27, 28, 29, 30, 31}},
        {"All zeros",
         {0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0}},
        {"All 0xFF",
         {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);
    for (size_t i = 0; i < num_tests; i++)
    {
        cid_v1_t cid, cid_from_bytes, cid_from_str;
        uint8_t bin[CIDV1_BINARY_SIZE];
        char str[128];
        uint8_t mh[CIDV1_MULTIHASH_SIZE];
        mh[0] = 0x12;
        mh[1] = 0x20;
        memcpy(mh + 2, tests[i].digest, CIDV1_DIGEST_SIZE);

        sprintf(test_name, "cid_v1_init(%s)", tests[i].description);
        ret = cid_v1_init(&cid, MULTICODEC_RAW, mh, CIDV1_MULTIHASH_SIZE);
        if (ret != CIDV1_SUCCESS)
        {
            char details[256];
            sprintf(details, "cid_v1_init returned error code %d", ret);
            print_standard(test_name, details, 0);
            failures++;
            continue;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v1_to_bytes(%s)", tests[i].description);
        ret = cid_v1_to_bytes(&cid, bin, sizeof(bin));
        if (ret != CIDV1_BINARY_SIZE)
        {
            char details[256];
            sprintf(details, "Expected %d bytes, got %d", CIDV1_BINARY_SIZE, ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (bin[0] != 0x01)
        {
            char details[256];
            sprintf(details, "Binary version byte mismatch for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (bin[1] != MULTICODEC_RAW)
        {
            char details[256];
            sprintf(details, "Binary content codec mismatch for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (memcmp(bin + 2, mh, CIDV1_MULTIHASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Binary multihash mismatch for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v1_from_bytes(%s)", tests[i].description);
        ret = cid_v1_from_bytes(&cid_from_bytes, bin, sizeof(bin));
        if (ret != CIDV1_BINARY_SIZE)
        {
            char details[256];
            sprintf(details, "Expected %d bytes consumed, got %d", CIDV1_BINARY_SIZE, ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (cid_from_bytes.version != 1 || cid_from_bytes.codec != MULTICODEC_RAW ||
                 cid_from_bytes.multihash_size != CIDV1_MULTIHASH_SIZE ||
                 memcmp(cid_from_bytes.multihash, mh, CIDV1_MULTIHASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Decoded CID does not match original for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&cid_from_bytes);

        sprintf(test_name, "cid_v1_to_string(%s)", tests[i].description);
        ret = cid_v1_to_string(&cid, MULTIBASE_BASE58_BTC, str, sizeof(str));
        if (ret < 0)
        {
            char details[256];
            sprintf(details, "cid_v1_to_string returned error code %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (str[0] != 'z')
        {
            char details[256];
            sprintf(details, "String does not start with 'z' for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        sprintf(test_name, "cid_v1_from_string(%s)", tests[i].description);
        ret = cid_v1_from_string(&cid_from_str, str);
        if (ret < 0)
        {
            char details[256];
            sprintf(details, "cid_v1_from_string returned error code %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else if (cid_from_str.version != 1 || cid_from_str.codec != MULTICODEC_RAW ||
                 cid_from_str.multihash_size != CIDV1_MULTIHASH_SIZE ||
                 memcmp(cid_from_str.multihash, mh, CIDV1_MULTIHASH_SIZE) != 0)
        {
            char details[256];
            sprintf(details, "Decoded CID from string does not match original for %s", tests[i].description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&cid_from_str);

        sprintf(test_name, "cid_v1_to_human(%s)", tests[i].description);
        {
            char human[128];
            ret = cid_v1_to_human(&cid, MULTIBASE_BASE58_BTC, human, sizeof(human));
            if (ret < 0)
            {
                char details[256];
                sprintf(details, "cid_v1_to_human returned error code %d", ret);
                print_standard(test_name, details, 0);
                failures++;
            }
            else if (strstr(human, "cidv1") == NULL)
            {
                char details[256];
                sprintf(details, "Human-readable CID does not contain 'cidv1' for %s", tests[i].description);
                print_standard(test_name, details, 0);
                failures++;
            }
            else
            {
                print_standard(test_name, "", 1);
            }
        }

        cid_v1_free(&cid);
    }

    sprintf(test_name, "cid_v1_init(NULL, valid_mh, %d)", CIDV1_MULTIHASH_SIZE);
    {
        uint8_t valid_mh[CIDV1_MULTIHASH_SIZE] = {0};
        ret = cid_v1_init(NULL, MULTICODEC_RAW, valid_mh, CIDV1_MULTIHASH_SIZE);
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v1_to_bytes(NULL, buf, size)");
    {
        uint8_t buf[CIDV1_BINARY_SIZE];
        ret = cid_v1_to_bytes(NULL, buf, sizeof(buf));
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_to_bytes(valid_cid, NULL, size)");
    {
        cid_v1_t dummy;
        uint8_t dummy_mh[CIDV1_MULTIHASH_SIZE] = {0};
        cid_v1_init(&dummy, MULTICODEC_RAW, dummy_mh, CIDV1_MULTIHASH_SIZE);
        ret = cid_v1_to_bytes(&dummy, NULL, CIDV1_BINARY_SIZE);
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&dummy);
    }
    sprintf(test_name, "cid_v1_to_bytes(valid_cid, buf, too small)");
    {
        cid_v1_t dummy;
        uint8_t dummy_mh[CIDV1_MULTIHASH_SIZE] = {0};
        cid_v1_init(&dummy, MULTICODEC_RAW, dummy_mh, CIDV1_MULTIHASH_SIZE);
        uint8_t buf[CIDV1_BINARY_SIZE - 1];
        ret = cid_v1_to_bytes(&dummy, buf, sizeof(buf));
        if (ret != CIDV1_ERROR_BUFFER_TOO_SMALL)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_BUFFER_TOO_SMALL, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&dummy);
    }

    sprintf(test_name, "cid_v1_from_bytes(NULL, bin, size)");
    {
        uint8_t bin[CIDV1_BINARY_SIZE] = {0};
        ret = cid_v1_from_bytes(NULL, bin, sizeof(bin));
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_from_bytes(valid_cid, NULL, size)");
    {
        cid_v1_t dummy;
        uint8_t bin[CIDV1_BINARY_SIZE] = {0};
        ret = cid_v1_from_bytes(&dummy, NULL, sizeof(bin));
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_from_bytes(valid_cid, bin, too small)");
    {
        cid_v1_t dummy;
        uint8_t bin[CIDV1_BINARY_SIZE];
        ret = cid_v1_from_bytes(&dummy, bin, CIDV1_BINARY_SIZE - 1);
        if (ret != CIDV1_ERROR_DECODE_FAILURE)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_DECODE_FAILURE, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v1_to_string(NULL, buf, size)");
    {
        char buf[128];
        ret = cid_v1_to_string(NULL, MULTIBASE_BASE58_BTC, buf, sizeof(buf));
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_to_string(valid_cid, NULL, size)");
    {
        cid_v1_t dummy;
        uint8_t dummy_mh[CIDV1_MULTIHASH_SIZE] = {0};
        cid_v1_init(&dummy, MULTICODEC_RAW, dummy_mh, CIDV1_MULTIHASH_SIZE);
        ret = cid_v1_to_string(&dummy, MULTIBASE_BASE58_BTC, NULL, 128);
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&dummy);
    }
    sprintf(test_name, "cid_v1_to_string(valid_cid, buf, too small)");
    {
        cid_v1_t dummy;
        uint8_t dummy_mh[CIDV1_MULTIHASH_SIZE] = {0};
        cid_v1_init(&dummy, MULTICODEC_RAW, dummy_mh, CIDV1_MULTIHASH_SIZE);
        char buf[CIDV1_BINARY_SIZE];
        ret = cid_v1_to_string(&dummy, MULTIBASE_BASE58_BTC, buf, sizeof(buf));
        if (ret != CIDV1_ERROR_ENCODE_FAILURE)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_ENCODE_FAILURE, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&dummy);
    }

    sprintf(test_name, "cid_v1_from_string(NULL, valid_str)");
    {
        char valid_str[CIDV1_BINARY_SIZE * 2] = "z";
        ret = cid_v1_from_string(NULL, valid_str);
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_from_string(valid_cid, NULL)");
    {
        cid_v1_t dummy;
        ret = cid_v1_from_string(&dummy, NULL);
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_from_string(valid_cid, invalid_str)");
    {
        cid_v1_t dummy;
        char invalid_str[] = "abc123";
        ret = cid_v1_from_string(&dummy, invalid_str);
        if (ret != CIDV1_ERROR_DECODE_FAILURE)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_DECODE_FAILURE, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }

    sprintf(test_name, "cid_v1_to_human(NULL, base, buf, size)");
    {
        char buf[128];
        ret = cid_v1_to_human(NULL, MULTIBASE_BASE58_BTC, buf, sizeof(buf));
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
    }
    sprintf(test_name, "cid_v1_to_human(valid_cid, base, NULL, size)");
    {
        cid_v1_t dummy;
        uint8_t dummy_mh[CIDV1_MULTIHASH_SIZE] = {0};
        cid_v1_init(&dummy, MULTICODEC_RAW, dummy_mh, CIDV1_MULTIHASH_SIZE);
        ret = cid_v1_to_human(&dummy, MULTIBASE_BASE58_BTC, NULL, 128);
        if (ret != CIDV1_ERROR_NULL_POINTER)
        {
            char details[256];
            sprintf(details, "Expected CIDV1_ERROR_NULL_POINTER, got %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }
        cid_v1_free(&dummy);
    }
    {
        const char *cid_str = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        const char *expected_human = "base32 - cidv1 - dag_pb - sha2_256-c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a";
        cid_v1_t cid;
        char human[256];

        sprintf(test_name, "cid_v1_to_human(known vector)");
        ret = cid_v1_from_string(&cid, cid_str);
        if (ret < 0)
        {
            char details[256];
            sprintf(details, "cid_v1_from_string() returned error code %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            ret = cid_v1_to_human(&cid, MULTIBASE_BASE32, human, sizeof(human));
            if (ret < 0)
            {
                char details[256];
                sprintf(details, "cid_v1_to_human() returned error code %d", ret);
                print_standard(test_name, details, 0);
                failures++;
            }
            else if (strcmp(human, expected_human) != 0)
            {
                char details[256];
                sprintf(details, "Expected '%s', got '%s'", expected_human, human);
                print_standard(test_name, details, 0);
                failures++;
            }
            else
            {
                print_standard(test_name, "", 1);
            }
        }
        cid_v1_free(&cid);
    }
    {
        const char *cid_str = "zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA";
        const char *expected_human = "base58btc - cidv1 - raw - sha2_256-6e6ff7950a36187a801613426e858dce686cd7d7e3c0fc42ee0330072d245c95";
        cid_v1_t cid;
        char human[256];

        sprintf(test_name, "cid_v1_to_human(known vector, base58btc)");
        ret = cid_v1_from_string(&cid, cid_str);
        if (ret < 0)
        {
            char details[256];
            sprintf(details, "cid_v1_from_string() returned error code %d", ret);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            ret = cid_v1_to_human(&cid, MULTIBASE_BASE58_BTC, human, sizeof(human));
            if (ret < 0)
            {
                char details[256];
                sprintf(details, "cid_v1_to_human() returned error code %d", ret);
                print_standard(test_name, details, 0);
                failures++;
            }
            else if (strcmp(human, expected_human) != 0)
            {
                char details[256];
                sprintf(details, "Expected '%s', got '%s'", expected_human, human);
                print_standard(test_name, details, 0);
                failures++;
            }
            else
            {
                print_standard(test_name, "", 1);
            }
        }
        cid_v1_free(&cid);
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