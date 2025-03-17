#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/multibase/multibase.h"

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
} test_vector;

typedef struct
{
    multibase_t base;
    const char *name;
    char expected_prefix;
} encoding_info;

int main(void)
{
    int failures = 0;

    test_vector tests[] = {
        {""},
        {"f"},
        {"fo"},
        {"foo"},
        {"foob"},
        {"fooba"},
        {"foobar"}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    encoding_info encodings[] = {
        {MULTIBASE_BASE16, "base16 (lowercase)", 'f'},
        {MULTIBASE_BASE16_UPPER, "base16 (uppercase)", 'F'},
        {MULTIBASE_BASE32, "base32 (lowercase)", 'b'},
        {MULTIBASE_BASE32_UPPER, "base32 (uppercase)", 'B'},
        {MULTIBASE_BASE58_BTC, "base58btc", 'z'},
        {MULTIBASE_BASE64, "base64 (no padding)", 'm'},
        {MULTIBASE_BASE64_URL, "base64url (no padding)", 'u'},
        {MULTIBASE_BASE64_URL_PAD, "base64url (with padding)", 'U'}};
    size_t num_encodings = sizeof(encodings) / sizeof(encodings[0]);

    /* --- Normal encode-decode tests --- */
    for (size_t e = 0; e < num_encodings; e++)
    {
        encoding_info enc = encodings[e];
        for (size_t i = 0; i < num_tests; i++)
        {
            test_vector tv = tests[i];
            size_t input_len = strlen(tv.input);
            /* Allocate an output buffer generously */
            size_t out_buf_size = input_len * 10 + 10;
            char *encoded = malloc(out_buf_size);
            if (encoded == NULL)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            char test_name[128];
            sprintf(test_name, "multibase_encode [%s] (\"%s\")", enc.name, tv.input);
            int ret = multibase_encode(enc.base, (const uint8_t *)tv.input, input_len, encoded, out_buf_size);
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

            /* Check that the encoded string begins with the expected prefix */
            if (encoded[0] != enc.expected_prefix)
            {
                char details[256];
                sprintf(details, "Encoded string prefix '%c' does not match expected '%c'", encoded[0], enc.expected_prefix);
                print_standard(test_name, details, 0);
                failures++;
                free(encoded);
                continue;
            }
            else
            {
                print_standard(test_name, "", 1);
            }

            /* Perform round-trip decode test */
            size_t decode_buf_size = input_len + 10;
            uint8_t *decoded = malloc(decode_buf_size);
            if (decoded == NULL)
            {
                fprintf(stderr, "Memory allocation failed\n");
                free(encoded);
                exit(EXIT_FAILURE);
            }
            sprintf(test_name, "multibase_decode [%s] (\"%s\")", enc.name, encoded);
            int ret_dec = multibase_decode(enc.base, encoded, decoded, decode_buf_size);
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
                sprintf(details, "Decoded output does not match original input \"%s\"", tv.input);
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
    }

    /* --- Insufficient Buffer Tests --- */
    /* --- Insufficient Buffer Tests --- */
    for (size_t e = 0; e < num_encodings; e++)
    {
        encoding_info enc = encodings[e];
        for (size_t i = 0; i < num_tests; i++)
        {
            test_vector tv = tests[i];
            size_t input_len = strlen(tv.input);
            /* First, encode with a large buffer to determine the full required length */
            size_t large_buf_size = input_len * 10 + 10;
            char *full_encoded = malloc(large_buf_size);
            if (full_encoded == NULL)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }
            int full_ret = multibase_encode(enc.base, (const uint8_t *)tv.input, input_len, full_encoded, large_buf_size);
            if (full_ret < 0)
            {
                free(full_encoded);
                continue; /* Skip insufficient test if full encoding fails */
            }
            /* Allocate a buffer that is one byte smaller than the full required length */
            size_t insufficient_size = (size_t)full_ret - 1;
            char *insuff_encoded = malloc(insufficient_size);
            if (insuff_encoded == NULL)
            {
                fprintf(stderr, "Memory allocation failed\n");
                free(full_encoded);
                exit(EXIT_FAILURE);
            }
            int ret = multibase_encode(enc.base, (const uint8_t *)tv.input, input_len, insuff_encoded, insufficient_size);
            char test_name[128];  // Declare test_name here.
            sprintf(test_name, "multibase_encode insufficient buffer [%s] (\"%s\")", enc.name, tv.input);
            if (ret != MULTIBASE_ERR_BUFFER_TOO_SMALL)
            {
                char details[256];
                sprintf(details, "Expected MULTIBASE_ERR_BUFFER_TOO_SMALL for insufficient buffer, got %d", ret);
                print_standard(test_name, details, 0);
                failures++;
            }
            else
            {
                print_standard(test_name, "", 1);
            }
            free(full_encoded);
            free(insuff_encoded);
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