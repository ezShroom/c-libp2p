#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/multibase/multibase.h"
#include "multiformats/multibase/base58_btc.h"

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

typedef struct
{
    const char *description;
    const uint8_t *input;
    size_t input_len;
    const char *expected;
} base58_test_vector;

int main(void)
{
    int failures = 0;
    uint8_t binary_data[] = {0x00, 0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd};
    base58_test_vector tests[] = {
        {"Hello World!", (const uint8_t *)"Hello World!", strlen("Hello World!"), "2NEpo7TZRRrLZSi2U"},
        {"The quick brown fox jumps over the lazy dog.", (const uint8_t *)"The quick brown fox jumps over the lazy dog.", strlen("The quick brown fox jumps over the lazy dog."), "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"},
        {"0x0000287fb4cd", binary_data, sizeof(binary_data), "111233QC4"}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < num_tests; i++)
    {
        base58_test_vector tv = tests[i];
        size_t out_buf_size = tv.input_len * 2 + 50;
        char *encoded = malloc(out_buf_size);
        if (!encoded)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }

        int ret = base58_btc_encode(tv.input, tv.input_len, encoded, out_buf_size - 1);
        char test_name[128];
        sprintf(test_name, "base58_btc_encode(\"%s\")", tv.description);
        if (ret < 0)
        {
            char details[256];
            sprintf(details, "Error code %d returned", ret);
            print_standard(test_name, details, 0);
            failures++;
            free(encoded);
            continue;
        }
        encoded[ret] = '\0';

        if (strcmp(encoded, tv.expected) != 0)
        {
            char details[256];
            sprintf(details, "Encoded result \"%s\", expected \"%s\"", encoded, tv.expected);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        size_t decode_buf_size = tv.input_len + 50;
        uint8_t *decoded = malloc(decode_buf_size);
        if (!decoded)
        {
            fprintf(stderr, "Memory allocation failed\n");
            free(encoded);
            exit(EXIT_FAILURE);
        }
        int ret_dec = base58_btc_decode(encoded, decoded, decode_buf_size);
        sprintf(test_name, "base58_btc_decode(\"%s\")", encoded);
        if (ret_dec < 0)
        {
            char details[256];
            sprintf(details, "Error code %d returned", ret_dec);
            print_standard(test_name, details, 0);
            failures++;
            free(encoded);
            free(decoded);
            continue;
        }

        if ((size_t)ret_dec != tv.input_len || memcmp(decoded, tv.input, tv.input_len) != 0)
        {
            char details[256];
            sprintf(details, "Decoded result does not match original input \"%s\"", tv.description);
            print_standard(test_name, details, 0);
            failures++;
        }
        else
        {
            print_standard(test_name, "", 1);
        }

        free(encoded);
        free(decoded);
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