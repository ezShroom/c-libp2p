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
    const char *expected_base16;
    const char *expected_base16_upper;
    const char *expected_base32_lower;
    const char *expected_base32_upper;
} test_vector;

int main(void)
{
    int failures = 0;
    test_vector tests[] = {
        {"", "f", "F", "b", "B"},
        {"f", "f66", "F66", "bmy======", "BMY======"},
        {"fo", "f666f", "F666F", "bmzxq====", "BMZXQ===="},
        {"foo", "f666f6f", "F666F6F", "bmzxw6===", "BMZXW6==="},
        {"foob", "f666f6f62", "F666F6F62", "bmzxw6yq=", "BMZXW6YQ="},
        {"fooba", "f666f6f6261", "F666F6F6261", "bmzxw6ytb", "BMZXW6YTB"},
        {"foobar", "f666f6f626172", "F666F6F626172", "bmzxw6ytboi======", "BMZXW6YTBOI======"}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    /* Array of the supported multibase types with descriptive names */
    struct
    {
        multibase_t base;
        const char *name;
    } bases[] = {
        {MULTIBASE_BASE16, "MULTIBASE_BASE16"},
        {MULTIBASE_BASE16_UPPER, "MULTIBASE_BASE16_UPPER"},
        {MULTIBASE_BASE32, "MULTIBASE_BASE32"},
        {MULTIBASE_BASE32_UPPER, "MULTIBASE_BASE32_UPPER"}};
    size_t num_bases = sizeof(bases) / sizeof(bases[0]);

    for (size_t i = 0; i < num_tests; i++)
    {
        for (size_t j = 0; j < num_bases; j++)
        {
            const char *input = tests[i].input;
            size_t input_len = strlen(input);
            const char *expected = NULL;
            switch (bases[j].base)
            {
            case MULTIBASE_BASE16:
                expected = tests[i].expected_base16;
                break;
            case MULTIBASE_BASE16_UPPER:
                expected = tests[i].expected_base16_upper;
                break;
            case MULTIBASE_BASE32:
                expected = tests[i].expected_base32_lower;
                break;
            case MULTIBASE_BASE32_UPPER:
                expected = tests[i].expected_base32_upper;
                break;
            default:
                break;
            }

            size_t out_buf_size = 0;
            if (bases[j].base == MULTIBASE_BASE16 || bases[j].base == MULTIBASE_BASE16_UPPER)
            {
                out_buf_size = input_len * 2 + 2;
            }
            else
            {
                size_t blocks = (input_len == 0) ? 0 : ((input_len + 4) / 5);
                out_buf_size = (blocks > 0 ? (blocks * 8 + 1) : 1) + 1;
            }

            char *encoded = malloc(out_buf_size);
            if (!encoded)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multibase_encode(bases[j].base, (const uint8_t *)input, input_len, encoded, out_buf_size);
            char test_name[128];
            sprintf(test_name, "%s_encode(\"%s\")", bases[j].name, input);
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

            if (strcmp(encoded, expected) != 0)
            {
                char details[256];
                sprintf(details, "Encoded result \"%s\", expected \"%s\"", encoded, expected);
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
            int ret_dec = multibase_decode(bases[j].base, encoded, decoded, decode_buf_size);
            sprintf(test_name, "%s_decode(\"%s\")", bases[j].name, encoded);
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

            if ((size_t)ret_dec != input_len || memcmp(decoded, input, input_len) != 0)
            {
                char details[256];
                sprintf(details, "Decoded result does not match original input \"%s\"", input);
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
