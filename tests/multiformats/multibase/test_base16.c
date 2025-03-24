#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/multibase/multibase.h"
#include "multiformats/multibase/encoding/base16.h"

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
    const char *input;
    const char *expected;
} base16_test_vector;

int main(void)
{
    int failures = 0;
    base16_test_vector tests[] = {
        {"", ""},
        {"f", "66"},
        {"fo", "666f"},
        {"foo", "666f6f"},
        {"foob", "666f6f62"},
        {"fooba", "666f6f6261"},
        {"foobar", "666f6f626172"}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < num_tests; i++)
    {
        base16_test_vector tv = tests[i];
        size_t input_len = strlen(tv.input);
        size_t out_buf_size = input_len * 2 + 1;
        char *encoded = malloc(out_buf_size);
        if (!encoded)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }

        int ret = base16_encode((const uint8_t *)tv.input, input_len, encoded, out_buf_size);
        char test_name[128];
        sprintf(test_name, "base16_encode(\"%s\")", tv.input);
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

        size_t decode_buf_size = input_len + 1;
        uint8_t *decoded = malloc(decode_buf_size);
        if (!decoded)
        {
            fprintf(stderr, "Memory allocation failed\n");
            free(encoded);
            exit(EXIT_FAILURE);
        }
        int ret_dec = base16_decode(encoded, ret, decoded, decode_buf_size);
        sprintf(test_name, "base16_decode(\"%s\")", encoded);
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

        if ((size_t)ret_dec != input_len || memcmp(decoded, tv.input, input_len) != 0)
        {
            char details[256];
            sprintf(details, "Decoded result does not match original input \"%s\"", tv.input);
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