#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/multihash/multihash.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-50s | PASS\n", test_name);
    else
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
}

static int hex_char_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *buf, size_t buf_size)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return -1;
    size_t bytes_needed = hex_len / 2;
    if (bytes_needed > buf_size)
        return -1;
    for (size_t i = 0; i < bytes_needed; i++)
    {
        int high = hex_char_to_int(hex[2 * i]);
        int low = hex_char_to_int(hex[2 * i + 1]);
        if (high < 0 || low < 0)
            return -1;
        buf[i] = (high << 4) | low;
    }
    return (int)bytes_needed;
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *hex_out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(hex_out + (i * 2), "%02x", in[i]);
    hex_out[len * 2] = '\0';
}

typedef struct
{
    const char *input;
    const char *expected_sha1;     // Expected multihash in hex for SHA1.
    const char *expected_sha256;   // Expected multihash in hex for SHA2-256.
    const char *expected_sha512;   // Expected multihash in hex for SHA2-512.
    const char *expected_sha3_224; // Expected multihash in hex for SHA3-224.
    const char *expected_sha3_256; // Expected multihash in hex for SHA3-256.
    const char *expected_sha3_384; // Expected multihash in hex for SHA3-384.
    const char *expected_sha3_512; // Expected multihash in hex for SHA3-512.
} test_vector;

int main(void)
{
    int failures = 0;
    test_vector tests[] = {
        {"",
         "1114da39a3ee5e6b4b0d3255bfef95601890afd80709",
         "1220e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "1340cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
         "171c6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
         "1620a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
         "15300c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
         "1440a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"},
        {"foo",
         "11140beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33",
         "12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
         "1340f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
         "171cf4f6779e153c391bbd29c95e72b0708e39d9166c7cea51d1f10ef58a",
         "162076d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01",
         "1530665551928d13b7d84ee02734502b018d896a0fb87eed5adb4c87ba91bbd6489410e11b0fbcc06ed7d0ebad559e5d3bb5",
         "14404bca2b137edc580fe50a88983ef860ebaca36c857b1f492839d6d7392452a63c82cbebc68e3b70a2a1480b4bb5d437a7cba6ecf9d89f9ff3ccd14cd6146ea7e7"},
        {"foobar",
         "11148843d7f92416211de9ebb963ff4ce28125932878",
         "1220c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
         "13400a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425",
         "171c1ad852ba147a715fe5a3df39a741fad08186c303c7d21cefb7be763b",
         "162009234807e4af85f17c66b48ee3bca89dffd1f1233659f9f940a2b17b0b8c6bc5",
         "15300fa8abfbdaf924ad307b74dd2ed183b9a4a398891a2f6bac8fd2db7041b77f068580f9c6c66f699b496c2da1cbcc7ed8",
         "1440ff32a30c3af5012ea395827a3e99a13073c3a8d8410a708568ff7e6eb85968fccfebaea039bc21411e9d43fdb9a851b529b9960ffea8679199781b8f45ca85e2"}};
    size_t num_tests = sizeof(tests) / sizeof(tests[0]);
    char test_name[256];

    for (size_t i = 0; i < num_tests; i++)
    {
        const char *input = tests[i].input;
        size_t input_len = strlen(input);

        // -----------------------
        // Test for SHA1.
        // -----------------------
        {
            /* For SHA1: 1 byte (code) + 1 byte (length) + 20-byte digest = 22 bytes. */
            size_t binary_buf_size = 22;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA1, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA1(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha1) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha1);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA1. */
                size_t decode_buf_size = 32; /* Sufficient for SHA1 digest (20 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA1(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 20)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 20", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    const char *expected_digest_hex = tests[i].expected_sha1 + 4;
                    uint8_t expected_digest[20];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 20)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 20) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
        }

        // -----------------------
        // Test for SHA2-256.
        // -----------------------
        {
            /* For SHA2-256: 1 byte (code) + 1 byte (length) + 32-byte digest = 34 bytes. */
            size_t binary_buf_size = 34;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA2_256, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA256(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha256) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha256);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA2-256. */
                size_t decode_buf_size = 64; /* Sufficient for SHA256 digest (32 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA256(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 32)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 32", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    const char *expected_digest_hex = tests[i].expected_sha256 + 4;
                    uint8_t expected_digest[32];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 32)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 32) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
        }

        // -----------------------
        // Test for SHA2-512.
        // -----------------------
        {
            /* For SHA2-512: 1 byte (code) + 1 byte (length) + 64-byte digest = 66 bytes. */
            size_t binary_buf_size = 66;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA2_512, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA512(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha512) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha512);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA2-512. */
                size_t decode_buf_size = 128; /* Sufficient for SHA512 digest (64 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA512(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 64)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 64", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    const char *expected_digest_hex = tests[i].expected_sha512 + 4;
                    uint8_t expected_digest[64];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 64)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 64) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
        }

        // -----------------------
        // Test for SHA3-224.
        // -----------------------
        {
            /* For SHA3-224: 1 byte (code) + 1 byte (length) + 28-byte digest = 30 bytes. */
            size_t binary_buf_size = 30;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA3_224, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA3_224(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha3_224) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha3_224);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA3-224. */
                size_t decode_buf_size = 40; /* Sufficient for SHA3-224 digest (28 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA3_224(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 28)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 28", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    /* The expected digest portion starts after the first 4 hex digits (2 bytes for code and length). */
                    const char *expected_digest_hex = tests[i].expected_sha3_224 + 4;
                    uint8_t expected_digest[28];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 28)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 28) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
        }

        // -----------------------
        // Test for SHA3-256.
        // -----------------------
        {
            /* For SHA3-256: 1 byte (code) + 1 byte (length) + 32-byte digest = 34 bytes. */
            size_t binary_buf_size = 34;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA3_256, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA3_256(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha3_256) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha3_256);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA3-256. */
                size_t decode_buf_size = 64; /* Sufficient for SHA3-256 digest (32 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA3_256(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 32)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 32", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    const char *expected_digest_hex = tests[i].expected_sha3_256 + 4;
                    uint8_t expected_digest[32];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 32)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 32) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
        }

        // -----------------------
        // Test for SHA3-384.
        // -----------------------
        {
            /* For SHA3-384: 1 byte (code) + 1 byte (length) + 48-byte digest = 50 bytes. */
            size_t binary_buf_size = 50;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA3_384, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA3_384(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha3_384) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha3_384);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA3-384. */
                size_t decode_buf_size = 64; /* Sufficient for SHA3-384 digest (48 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA3_384(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 48)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 48", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    const char *expected_digest_hex = tests[i].expected_sha3_384 + 4;
                    uint8_t expected_digest[48];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 48)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 48) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
        }

        // -----------------------
        // Test for SHA3-512.
        // -----------------------
        {
            /* For SHA3-512: 1 byte (code) + 1 byte (length) + 64-byte digest = 66 bytes. */
            size_t binary_buf_size = 66;
            uint8_t *binary_hash = malloc(binary_buf_size);
            if (!binary_hash)
            {
                fprintf(stderr, "Memory allocation failed\n");
                exit(EXIT_FAILURE);
            }

            int ret = multihash_encode(MULTICODEC_SHA3_512, (const uint8_t *)input, input_len, binary_hash, binary_buf_size);
            snprintf(test_name, sizeof(test_name), "MULTIHASH_encode_SHA3_512(\"%s\")", input);
            if (ret < 0)
            {
                char details[256];
                snprintf(details, sizeof(details), "Error code %d returned", ret);
                print_standard(test_name, details, 0);
                failures++;
                free(binary_hash);
            }
            else
            {
                size_t binary_hash_len = ret;
                char *hex_output = malloc(binary_hash_len * 2 + 1);
                if (!hex_output)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    exit(EXIT_FAILURE);
                }
                bytes_to_hex(binary_hash, binary_hash_len, hex_output);

                if (strcmp(hex_output, tests[i].expected_sha3_512) != 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Encoded result \"%s\", expected \"%s\"", hex_output, tests[i].expected_sha3_512);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    print_standard(test_name, "", 1);
                }

                /* Test decoding for SHA3-512. */
                size_t decode_buf_size = 128; /* Sufficient for SHA3-512 digest (64 bytes) */
                uint8_t *decoded = malloc(decode_buf_size);
                if (!decoded)
                {
                    fprintf(stderr, "Memory allocation failed\n");
                    free(binary_hash);
                    free(hex_output);
                    exit(EXIT_FAILURE);
                }
                uint64_t code = 0;
                size_t digest_len = decode_buf_size;
                int ret_dec = multihash_decode(binary_hash, binary_hash_len, &code, decoded, &digest_len);
                snprintf(test_name, sizeof(test_name), "MULTIHASH_decode_SHA3_512(\"%s\")", hex_output);
                if (ret_dec < 0)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Error code %d returned", ret_dec);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else if (digest_len != 64)
                {
                    char details[256];
                    snprintf(details, sizeof(details), "Decoded digest length %zu, expected 64", digest_len);
                    print_standard(test_name, details, 0);
                    failures++;
                }
                else
                {
                    const char *expected_digest_hex = tests[i].expected_sha3_512 + 4;
                    uint8_t expected_digest[64];
                    int res = hex_to_bytes(expected_digest_hex, expected_digest, sizeof(expected_digest));
                    if (res < 0 || (size_t)res != 64)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Error converting expected digest hex to bytes");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else if (memcmp(decoded, expected_digest, 64) != 0)
                    {
                        char details[256];
                        snprintf(details, sizeof(details), "Decoded digest does not match expected digest");
                        print_standard(test_name, details, 0);
                        failures++;
                    }
                    else
                    {
                        print_standard(test_name, "", 1);
                    }
                }
                free(binary_hash);
                free(hex_output);
                free(decoded);
            }
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