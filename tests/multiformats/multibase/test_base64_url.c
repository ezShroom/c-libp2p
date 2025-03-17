#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/multibase/multibase.h"
#include "multiformats/multibase/base64_url.h"

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
} base64url_test_vector;

int main(void)
{
    int failures = 0;
    base64url_test_vector tests[] = {
        {"", ""},
        {"f", "Zg"},
        {"fo", "Zm8"},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg"},
        {"fooba", "Zm9vYmE"},
        {"foobar", "Zm9vYmFy"},
        {"foo+bar/baz", "Zm9vK2Jhci9iYXo"},
        {"ladies and gentlemen, we are floating in space", "bGFkaWVzIGFuZCBnZW50bGVtZW4sIHdlIGFyZSBmbG9hdGluZyBpbiBzcGFjZQ"}
    };
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < num_tests; i++)
    {
        base64url_test_vector tv = tests[i];
        size_t input_len = strlen(tv.input);
        size_t out_buf_size = ((input_len + 2) / 3) * 4 + 1;
        char *encoded = malloc(out_buf_size);
        if (encoded == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            exit(EXIT_FAILURE);
        }
        int ret = base64_url_encode((const uint8_t *)tv.input, input_len, encoded, out_buf_size - 1);
        char test_name[128];
        sprintf(test_name, "base64_url_encode(\"%s\")", tv.input);
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
        if (decoded == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            free(encoded);
            exit(EXIT_FAILURE);
        }
        int ret_dec = base64_url_decode(encoded, decoded, decode_buf_size);
        sprintf(test_name, "base64_url_decode(\"%s\")", encoded);
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
        if (((size_t)ret_dec != input_len) || (memcmp(decoded, tv.input, input_len) != 0))
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