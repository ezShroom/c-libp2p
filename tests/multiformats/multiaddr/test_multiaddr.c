#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multibase/multibase.h"
#include "multiformats/multicodec/multicodec_codes.h"

struct multiaddr_s
{
    size_t size;    /* Number of bytes in 'bytes' */
    uint8_t *bytes; /* The raw, serialized multiaddr data */
};

/* Helper printing function for test results */
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

/* Test multiaddr_new_from_str and multiaddr_to_str */
static int test_new_from_str(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma)
    {
        print_standard("multiaddr_new_from_str valid",
                       "Returned NULL for valid multiaddr", 0);
        failures++;
    }
    else if (err != MULTIADDR_SUCCESS)
    {
        char details[256];
        sprintf(details, "Error code %d returned for valid multiaddr", err);
        print_standard("multiaddr_new_from_str valid", details, 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(ma, &err);
        if (!s)
        {
            print_standard("multiaddr_to_str after new_from_str",
                           "Returned NULL", 0);
            failures++;
        }
        else if (strcmp(s, "/ip4/127.0.0.1/tcp/80") != 0)
        {
            char details[256];
            sprintf(details, "Got \"%s\", expected \"/ip4/127.0.0.1/tcp/80\"", s);
            print_standard("multiaddr_to_str valid", details, 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_new_from_str valid", "", 1);
        }
        free(s);
        multiaddr_free(ma);
    }

    /* Test valid multiaddr with p2p component */
    ma = multiaddr_new_from_str(
           "/ip4/127.0.0.1/tcp/80/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N", &err);
    if (!ma)
    {
        print_standard("multiaddr_new_from_str valid p2p",
                       "Returned NULL for valid p2p multiaddr", 0);
        failures++;
    }
    else if (err != MULTIADDR_SUCCESS)
    {
        char details[256];
        sprintf(details, "Error code %d returned for valid p2p multiaddr", err);
        print_standard("multiaddr_new_from_str valid p2p", details, 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(ma, &err);
        if (!s)
        {
            print_standard("multiaddr_to_str p2p", "Returned NULL", 0);
            failures++;
        }
        else
        {
            const char *expected = "/ip4/127.0.0.1/tcp/80/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
            if (strcmp(s, expected) != 0)
            {
                char details[256];
                sprintf(details, "Got \"%s\", expected \"%s\"", s, expected);
                print_standard("multiaddr_to_str valid p2p", details, 0);
                failures++;
            }
            else
            {
                print_standard("multiaddr_new_from_str valid p2p", "", 1);
            }
            free(s);
        }
        multiaddr_free(ma);
    }

    /* Test error: NULL pointer input */
    ma = multiaddr_new_from_str(NULL, &err);
    if (ma != NULL || err != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_new_from_str NULL input",
                       "Did not return NULL or correct error for NULL input", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_new_from_str NULL input", "", 1);
    }

    /* Test error: string not starting with '/' */
    ma = multiaddr_new_from_str("ip4/127.0.0.1", &err);
    if (ma != NULL || err != MULTIADDR_ERR_INVALID_STRING)
    {
        print_standard("multiaddr_new_from_str missing leading '/'",
                       "Did not return error for missing leading '/'", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_new_from_str missing leading '/'", "", 1);
    }

    /* Test error: incomplete multiaddr (e.g. missing tcp port) */
    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp", &err);
    if (ma != NULL || err != MULTIADDR_ERR_INVALID_STRING)
    {
        print_standard("multiaddr_new_from_str incomplete",
                       "Did not return error for incomplete multiaddr", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_new_from_str incomplete", "", 1);
    }

    return failures;
}

/* Test creating multiaddr from raw bytes */
static int test_new_from_bytes(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma1 = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma1)
    {
        print_standard("multiaddr_new_from_bytes setup",
                       "Failed to create multiaddr from string", 0);
        return 1;
    }
    multiaddr_t *ma2 = multiaddr_new_from_bytes(ma1->bytes, ma1->size, &err);
    if (!ma2 || err != MULTIADDR_SUCCESS)
    {
        print_standard("multiaddr_new_from_bytes valid",
                       "Failed to create multiaddr from bytes", 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(ma2, &err);
        if (!s || strcmp(s, "/ip4/127.0.0.1/tcp/80") != 0)
        {
            print_standard("multiaddr_new_from_bytes valid",
                           "String conversion mismatch", 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_new_from_bytes valid", "", 1);
        }
        free(s);
    }
    multiaddr_free(ma1);
    multiaddr_free(ma2);

    /* Test error: NULL bytes pointer */
    ma2 = multiaddr_new_from_bytes(NULL, 10, &err);
    if (ma2 != NULL || err != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_new_from_bytes NULL input",
                       "Did not return error for NULL bytes pointer", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_new_from_bytes NULL input", "", 1);
    }

    return failures;
}

/* Test multiaddr_copy */
static int test_copy(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma1 = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma1)
    {
        print_standard("multiaddr_copy setup", "Failed to create multiaddr", 0);
        return 1;
    }
    multiaddr_t *ma_copy = multiaddr_copy(ma1, &err);
    if (!ma_copy || err != MULTIADDR_SUCCESS)
    {
        print_standard("multiaddr_copy valid", "Failed to copy multiaddr", 0);
        failures++;
    }
    else
    {
        char *s1 = multiaddr_to_str(ma1, &err);
        char *s2 = multiaddr_to_str(ma_copy, &err);
        if (!s1 || !s2 || strcmp(s1, s2) != 0)
        {
            print_standard("multiaddr_copy valid",
                           "Copied multiaddr string does not match original", 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_copy valid", "", 1);
        }
        free(s1);
        free(s2);
    }
    multiaddr_free(ma1);
    multiaddr_free(ma_copy);

    /* Test error: NULL input */
    ma_copy = multiaddr_copy(NULL, &err);
    if (ma_copy != NULL || err != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_copy NULL input",
                       "Did not return error for NULL input", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_copy NULL input", "", 1);
    }

    return failures;
}

/* Test multiaddr_get_bytes */
static int test_get_bytes(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma)
    {
        print_standard("multiaddr_get_bytes setup", "Failed to create multiaddr", 0);
        return 1;
    }

    /* Test with insufficient buffer */
    uint8_t buf[10];
    size_t buf_len = 2; /* intentionally too small */
    int ret = multiaddr_get_bytes(ma, buf, buf_len);
    if (ret != MULTIADDR_ERR_BUFFER_TOO_SMALL)
    {
        print_standard("multiaddr_get_bytes small buffer",
                       "Did not return BUFFER_TOO_SMALL error", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_bytes small buffer", "", 1);
    }

    /* Test with sufficient buffer */
    buf_len = ma->size;
    memset(buf, 0, sizeof(buf));
    ret = multiaddr_get_bytes(ma, buf, buf_len);
    if (ret != (int)ma->size)
    {
        print_standard("multiaddr_get_bytes valid buffer",
                       "Returned incorrect byte count", 0);
        failures++;
    }
    else if (memcmp(buf, ma->bytes, ma->size) != 0)
    {
        print_standard("multiaddr_get_bytes valid buffer",
                       "Buffer contents do not match", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_bytes valid buffer", "", 1);
    }
    multiaddr_free(ma);

    /* Test error: NULL multiaddr or buffer */
    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    ret = multiaddr_get_bytes(NULL, buf, buf_len);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_bytes NULL multiaddr",
                       "Did not return error for NULL multiaddr", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_bytes NULL multiaddr", "", 1);
    }
    ret = multiaddr_get_bytes(ma, NULL, buf_len);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_bytes NULL buffer",
                       "Did not return error for NULL buffer", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_bytes NULL buffer", "", 1);
    }
    multiaddr_free(ma);

    return failures;
}

/* Test multiaddr_nprotocols */
static int test_nprotocols(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma)
    {
        print_standard("multiaddr_nprotocols ip4/tcp",
                       "Failed to create multiaddr", 0);
        return 1;
    }
    size_t n = multiaddr_nprotocols(ma);
    if (n != 2)
    {
        char details[128];
        sprintf(details, "Expected 2 protocols, got %zu", n);
        print_standard("multiaddr_nprotocols ip4/tcp", details, 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_nprotocols ip4/tcp", "", 1);
    }
    multiaddr_free(ma);

    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80/ws", &err);
    if (!ma)
    {
        print_standard("multiaddr_nprotocols ip4/tcp/ws",
                       "Failed to create multiaddr", 0);
        return failures + 1;
    }
    n = multiaddr_nprotocols(ma);
    if (n != 3)
    {
        char details[128];
        sprintf(details, "Expected 3 protocols, got %zu", n);
        print_standard("multiaddr_nprotocols ip4/tcp/ws", details, 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_nprotocols ip4/tcp/ws", "", 1);
    }
    multiaddr_free(ma);

    /* Test with NULL multiaddr */
    n = multiaddr_nprotocols(NULL);
    if (n != 0)
    {
        print_standard("multiaddr_nprotocols NULL",
                       "Expected 0 protocols for NULL input", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_nprotocols NULL", "", 1);
    }

    return failures;
}

/* Test multiaddr_get_protocol_code */
static int test_get_protocol_code(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma)
    {
        print_standard("multiaddr_get_protocol_code setup",
                       "Failed to create multiaddr", 0);
        return 1;
    }
    uint64_t code;
    int ret = multiaddr_get_protocol_code(ma, 0, &code);
    if (ret != 0 || code != MULTICODEC_IP4)
    {
        char details[128];
        sprintf(details, "Index 0: got 0x%llx, expected 0x%llx",
                (unsigned long long)code, (unsigned long long)MULTICODEC_IP4);
        print_standard("multiaddr_get_protocol_code index 0", details, 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_protocol_code index 0", "", 1);
    }

    ret = multiaddr_get_protocol_code(ma, 1, &code);
    if (ret != 0 || code != MULTICODEC_TCP)
    {
        char details[128];
        sprintf(details, "Index 1: got 0x%llx, expected 0x%llx",
                (unsigned long long)code, (unsigned long long)MULTICODEC_TCP);
        print_standard("multiaddr_get_protocol_code index 1", details, 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_protocol_code index 1", "", 1);
    }

    /* Test invalid index */
    ret = multiaddr_get_protocol_code(ma, 2, &code);
    if (ret != MULTIADDR_ERR_INVALID_DATA)
    {
        print_standard("multiaddr_get_protocol_code invalid index",
                       "Did not return error for invalid index", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_protocol_code invalid index", "", 1);
    }

    /* Test error: NULL input */
    ret = multiaddr_get_protocol_code(NULL, 0, &code);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_protocol_code NULL multiaddr",
                       "Did not return error for NULL multiaddr", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_protocol_code NULL multiaddr", "", 1);
    }
    ret = multiaddr_get_protocol_code(ma, 0, NULL);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_protocol_code NULL output",
                       "Did not return error for NULL proto_out", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_protocol_code NULL output", "", 1);
    }

    multiaddr_free(ma);
    return failures;
}

/* Test multiaddr_get_address_bytes */
static int test_get_address_bytes(void)
{
    int failures = 0;
    int err = 0;
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    if (!ma)
    {
        print_standard("multiaddr_get_address_bytes setup",
                       "Failed to create multiaddr", 0);
        return 1;
    }
    uint8_t buf[32];
    size_t buf_len = sizeof(buf);

    /* Test index 0 (ip4): expect 4 bytes {127, 0, 0, 1} */
    buf_len = 2; /* intentionally too small */
    int ret = multiaddr_get_address_bytes(ma, 0, buf, &buf_len);
    if (ret != MULTIADDR_ERR_BUFFER_TOO_SMALL || buf_len != 4)
    {
        print_standard("multiaddr_get_address_bytes small buffer",
                       "Did not return BUFFER_TOO_SMALL for index 0", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_address_bytes small buffer", "", 1);
    }
    buf_len = 4;
    ret = multiaddr_get_address_bytes(ma, 0, buf, &buf_len);
    if (ret != 0)
    {
        print_standard("multiaddr_get_address_bytes index 0",
                       "Failed to get address bytes for index 0", 0);
        failures++;
    }
    else
    {
        uint8_t expected[4] = {127, 0, 0, 1};
        if (memcmp(buf, expected, 4) != 0)
        {
            print_standard("multiaddr_get_address_bytes index 0",
                           "Address bytes do not match expected", 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_get_address_bytes index 0", "", 1);
        }
    }

    /* Test index 1 (tcp): expect 2 bytes for port 80 (0x00 0x50) */
    buf_len = 1; /* too small */
    ret = multiaddr_get_address_bytes(ma, 1, buf, &buf_len);
    if (ret != MULTIADDR_ERR_BUFFER_TOO_SMALL || buf_len != 2)
    {
        print_standard("multiaddr_get_address_bytes small buffer index 1",
                       "Did not return BUFFER_TOO_SMALL for index 1", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_address_bytes small buffer index 1", "", 1);
    }
    buf_len = 2;
    ret = multiaddr_get_address_bytes(ma, 1, buf, &buf_len);
    if (ret != 0)
    {
        print_standard("multiaddr_get_address_bytes index 1",
                       "Failed to get address bytes for index 1", 0);
        failures++;
    }
    else
    {
        uint8_t expected[2] = {0, 80}; /* port 80 = 0x0050 */
        if (memcmp(buf, expected, 2) != 0)
        {
            print_standard("multiaddr_get_address_bytes index 1",
                           "TCP port bytes do not match expected", 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_get_address_bytes index 1", "", 1);
        }
    }

    /* Test error: NULL pointers */
    ret = multiaddr_get_address_bytes(NULL, 0, buf, &buf_len);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_address_bytes NULL multiaddr",
                       "Did not return error for NULL multiaddr", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_address_bytes NULL multiaddr", "", 1);
    }
    ret = multiaddr_get_address_bytes(ma, 0, NULL, &buf_len);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_address_bytes NULL buffer",
                       "Did not return error for NULL buffer", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_address_bytes NULL buffer", "", 1);
    }
    ret = multiaddr_get_address_bytes(ma, 0, buf, NULL);
    if (ret != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_get_address_bytes NULL buf_len",
                       "Did not return error for NULL buf_len", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_get_address_bytes NULL buf_len", "", 1);
    }

    multiaddr_free(ma);
    return failures;
}

/* Test multiaddr_encapsulate */
static int test_encapsulate(void)
{
    int failures = 0;
    int err = 0;
    /* Create base multiaddr: /ip4/127.0.0.1 */
    multiaddr_t *ma1 = multiaddr_new_from_str("/ip4/127.0.0.1", &err);
    if (!ma1)
    {
        print_standard("multiaddr_encapsulate setup",
                       "Failed to create base multiaddr", 0);
        return 1;
    }
    /* Create encapsulated part: /tcp/80 */
    multiaddr_t *ma2 = multiaddr_new_from_str("/tcp/80", &err);
    if (!ma2)
    {
        print_standard("multiaddr_encapsulate setup",
                       "Failed to create encapsulated multiaddr", 0);
        multiaddr_free(ma1);
        return 1;
    }
    multiaddr_t *enc = multiaddr_encapsulate(ma1, ma2, &err);
    if (!enc || err != MULTIADDR_SUCCESS)
    {
        print_standard("multiaddr_encapsulate valid", "Encapsulation failed", 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(enc, &err);
        const char *expected = "/ip4/127.0.0.1/tcp/80";
        if (!s || strcmp(s, expected) != 0)
        {
            char details[256];
            sprintf(details, "Got \"%s\", expected \"%s\"", s ? s : "(null)", expected);
            print_standard("multiaddr_encapsulate valid", details, 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_encapsulate valid", "", 1);
        }
        free(s);
        multiaddr_free(enc);
    }
    multiaddr_free(ma1);
    multiaddr_free(ma2);

    /* Test error: NULL input */
    enc = multiaddr_encapsulate(NULL, ma1, &err);
    if (enc != NULL || err != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_encapsulate NULL input",
                       "Did not return error for NULL input", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_encapsulate NULL input", "", 1);
    }

    return failures;
}

/* Test multiaddr_decapsulate */
static int test_decapsulate(void)
{
    int failures = 0;
    int err = 0;

    /* Decapsulate /ws from /ip4/127.0.0.1/tcp/80/ws should yield /ip4/127.0.0.1/tcp/80 */
    multiaddr_t *ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80/ws", &err);
    multiaddr_t *sub = multiaddr_new_from_str("/ws", &err);
    if (!ma || !sub)
    {
        print_standard("multiaddr_decapsulate setup",
                       "Failed to create multiaddrs for decapsulation", 0);
        if (ma) multiaddr_free(ma);
        if (sub) multiaddr_free(sub);
        return 1;
    }
    multiaddr_t *dec = multiaddr_decapsulate(ma, sub, &err);
    if (!dec || err != MULTIADDR_SUCCESS)
    {
        print_standard("multiaddr_decapsulate valid /ws",
                       "Decapsulation failed", 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(dec, &err);
        const char *expected = "/ip4/127.0.0.1/tcp/80";
        if (!s || strcmp(s, expected) != 0)
        {
            char details[256];
            sprintf(details, "Got \"%s\", expected \"%s\"", s ? s : "(null)", expected);
            print_standard("multiaddr_decapsulate valid /ws", details, 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_decapsulate valid /ws", "", 1);
        }
        free(s);
        multiaddr_free(dec);
    }
    multiaddr_free(sub);
    multiaddr_free(ma);

    /* Decapsulate /tcp/80 from /ip4/127.0.0.1/tcp/80/ws should yield /ip4/127.0.0.1 */
    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80/ws", &err);
    sub = multiaddr_new_from_str("/tcp/80", &err);
    dec = multiaddr_decapsulate(ma, sub, &err);
    if (!dec || err != MULTIADDR_SUCCESS)
    {
        print_standard("multiaddr_decapsulate valid /tcp/80",
                       "Decapsulation failed", 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(dec, &err);
        const char *expected = "/ip4/127.0.0.1";
        if (!s || strcmp(s, expected) != 0)
        {
            char details[256];
            sprintf(details, "Got \"%s\", expected \"%s\"", s ? s : "(null)", expected);
            print_standard("multiaddr_decapsulate valid /tcp/80", details, 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_decapsulate valid /tcp/80", "", 1);
        }
        free(s);
        multiaddr_free(dec);
    }
    multiaddr_free(sub);
    multiaddr_free(ma);

    /* Decapsulate full multiaddr: decapsulating an entire address yields an empty multiaddr */
    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    sub = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    dec = multiaddr_decapsulate(ma, sub, &err);
    if (!dec || err != MULTIADDR_SUCCESS)
    {
        print_standard("multiaddr_decapsulate full decapsulation",
                       "Decapsulation failed", 0);
        failures++;
    }
    else
    {
        char *s = multiaddr_to_str(dec, &err);
        /* Expected empty string */
        if (!s || strcmp(s, "") != 0)
        {
            char details[256];
            sprintf(details, "Got \"%s\", expected empty string", s ? s : "(null)");
            print_standard("multiaddr_decapsulate full decapsulation", details, 0);
            failures++;
        }
        else
        {
            print_standard("multiaddr_decapsulate full decapsulation", "", 1);
        }
        free(s);
        multiaddr_free(dec);
    }
    multiaddr_free(sub);
    multiaddr_free(ma);

    /* Decapsulate with non-matching sub should return error */
    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    sub = multiaddr_new_from_str("/udp/80", &err);
    dec = multiaddr_decapsulate(ma, sub, &err);
    if (dec != NULL || err != MULTIADDR_ERR_NO_MATCH)
    {
        print_standard("multiaddr_decapsulate non-matching",
                       "Did not return error for non-matching sub", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_decapsulate non-matching", "", 1);
    }
    multiaddr_free(sub);
    multiaddr_free(ma);

    /* Test error: NULL input */
    ma = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/80", &err);
    dec = multiaddr_decapsulate(NULL, ma, &err);
    if (dec != NULL || err != MULTIADDR_ERR_NULL_POINTER)
    {
        print_standard("multiaddr_decapsulate NULL input",
                       "Did not return error for NULL input", 0);
        failures++;
    }
    else
    {
        print_standard("multiaddr_decapsulate NULL input", "", 1);
    }
    multiaddr_free(ma);

    return failures;
}

/* Main test runner */
int main(void)
{
    int failures = 0;

    failures += test_new_from_str();
    failures += test_new_from_bytes();
    failures += test_copy();
    failures += test_get_bytes();
    failures += test_nprotocols();
    failures += test_get_protocol_code();
    failures += test_get_address_bytes();
    failures += test_encapsulate();
    failures += test_decapsulate();

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