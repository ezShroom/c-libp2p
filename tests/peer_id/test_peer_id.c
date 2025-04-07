#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "peer_id/peer_id.h"
#include "peer_id/peer_id_secp256k1.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_ecdsa.h"
#include "peer_id/peer_id_rsa.h"

/* Helper function to print test results. */
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

/* Helper function: convert a hex string to a byte array.
   The caller must free the returned array.
*/
static uint8_t *hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
    {
        return NULL;
    }
    size_t bytes_len = hex_len / 2;
    uint8_t *bytes = malloc(bytes_len);
    if (!bytes)
    {
        return NULL;
    }
    for (size_t i = 0; i < bytes_len; i++)
    {
        char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    *out_len = bytes_len;
    return bytes;
}

/* Test vectors (hex-encoded) for secp256k1 keys from the spec */
#define SECP256K1_PUBLIC_HEX "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
#define SECP256K1_PRIVATE_HEX "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"

int main(void)
{
    int failures = 0;
    peer_id_error_t err;
    int ret;

    /***********************
     * Test 1: Create peer ID from a public key
     ***********************/
    {
        size_t pubkey_len = 0;
        uint8_t *pubkey = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pubkey_len);
        if (!pubkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 public hex to bytes\n");
            exit(EXIT_FAILURE);
        }

        peer_id_t pid_pub;
        pid_pub.bytes = NULL;
        pid_pub.size = 0;
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid_pub);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_public_key()", "Returned error", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_public_key()", "", 1);
        }
        free(pubkey);

        /* Test peer_id_to_string for legacy (base58btc) format. */
        char legacy_str[256];
        ret = peer_id_to_string(&pid_pub, PEER_ID_FMT_BASE58_LEGACY, legacy_str, sizeof(legacy_str));
        if (ret < 0)
        {
            print_standard("peer_id_to_string(legacy)", "Encoding failed", 0);
            failures++;
        }
        else
        {
            char details[256];
            sprintf(details, "Legacy string: %s", legacy_str);
            print_standard("peer_id_to_string(legacy)", details, 1);
        }

        /* Test peer_id_to_string for CIDv1 multibase format. */
        char cid_str[256];
        ret = peer_id_to_string(&pid_pub, PEER_ID_FMT_MULTIBASE_CIDv1, cid_str, sizeof(cid_str));
        if (ret < 0)
        {
            print_standard("peer_id_to_string(CIDv1)", "Encoding failed", 0);
            failures++;
        }
        else
        {
            char details[256];
            sprintf(details, "CIDv1 string: %s", cid_str);
            print_standard("peer_id_to_string(CIDv1)", details, 1);
        }

        peer_id_destroy(&pid_pub);
    }

    /***********************
     * Test 2: Create peer ID from a private key (secp256k1)
     ***********************/
    {
        size_t privkey_len = 0;
        uint8_t *privkey = hex_to_bytes(SECP256K1_PRIVATE_HEX, &privkey_len);
        if (!privkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 private hex to bytes\n");
            exit(EXIT_FAILURE);
        }

        peer_id_t pid_priv;
        pid_priv.bytes = NULL;
        pid_priv.size = 0;
        err = peer_id_create_from_private_key(privkey, privkey_len, &pid_priv);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_private_key()", "Returned error", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_private_key()", "", 1);
        }
        free(privkey);

        /* Also create peer ID from public key and compare. */
        size_t pubkey_len = 0;
        uint8_t *pubkey = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pubkey_len);
        if (!pubkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 public hex to bytes\n");
            exit(EXIT_FAILURE);
        }
        peer_id_t pid_pub;
        pid_pub.bytes = NULL;
        pid_pub.size = 0;
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid_pub);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_public_key() (for private key test)", "Returned error", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_public_key() (for private key test)", "", 1);
        }
        free(pubkey);

        int eq = peer_id_equals(&pid_priv, &pid_pub);
        if (eq != 1)
        {
            print_standard("peer_id_equals(private vs public)", "Peer IDs do not match", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_equals(private vs public)", "", 1);
        }
        peer_id_destroy(&pid_priv);
        peer_id_destroy(&pid_pub);
    }

    /***********************
     * Test 3: Create peer ID from string representation
     ***********************/
    {
        /* Legacy (raw base58btc) test */
        size_t pubkey_len = 0;
        uint8_t *pubkey = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pubkey_len);
        if (!pubkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 public hex to bytes\n");
            exit(EXIT_FAILURE);
        }
        peer_id_t pid;
        pid.bytes = NULL;
        pid.size = 0;
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid);
        free(pubkey);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_public_key() (for string test)", "Returned error", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_public_key() (for string test)", "", 1);
        }

        char legacy_str[256];
        ret = peer_id_to_string(&pid, PEER_ID_FMT_BASE58_LEGACY, legacy_str, sizeof(legacy_str));
        if (ret < 0)
        {
            print_standard("peer_id_to_string(legacy) (for string test)", "Encoding failed", 0);
            failures++;
        }
        else
        {
            char details[256];
            sprintf(details, "Legacy string: %s", legacy_str);
            print_standard("peer_id_to_string(legacy) (for string test)", details, 1);
        }

        peer_id_t pid_from_str;
        pid_from_str.bytes = NULL;
        pid_from_str.size = 0;
        err = peer_id_create_from_string(legacy_str, &pid_from_str);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_string(legacy)", "Decoding failed", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_string(legacy)", "", 1);
        }

        if (peer_id_equals(&pid, &pid_from_str) != 1)
        {
            print_standard("peer_id_equals(legacy)", "Decoded peer ID does not match original", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_equals(legacy)", "", 1);
        }
        peer_id_destroy(&pid);
        peer_id_destroy(&pid_from_str);

        /* CIDv1 (multibase) test */
        pubkey = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pubkey_len);
        if (!pubkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 public hex to bytes (CIDv1 test)\n");
            exit(EXIT_FAILURE);
        }
        pid.bytes = NULL;
        pid.size = 0;
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid);
        free(pubkey);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_public_key() (CIDv1 test)", "Returned error", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_public_key() (CIDv1 test)", "", 1);
        }

        char cid_str[256];
        ret = peer_id_to_string(&pid, PEER_ID_FMT_MULTIBASE_CIDv1, cid_str, sizeof(cid_str));
        if (ret < 0)
        {
            print_standard("peer_id_to_string(CIDv1) (for string test)", "Encoding failed", 0);
            failures++;
        }
        else
        {
            char details[256];
            sprintf(details, "CIDv1 string: %s", cid_str);
            print_standard("peer_id_to_string(CIDv1) (for string test)", details, 1);
        }

        peer_id_t pid_from_cid;
        pid_from_cid.bytes = NULL;
        pid_from_cid.size = 0;
        err = peer_id_create_from_string(cid_str, &pid_from_cid);
        if (err != PEER_ID_SUCCESS)
        {
            print_standard("peer_id_create_from_string(CIDv1)", "Decoding failed", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_create_from_string(CIDv1)", "", 1);
        }

        if (peer_id_equals(&pid, &pid_from_cid) != 1)
        {
            print_standard("peer_id_equals(CIDv1)", "Decoded CIDv1 peer ID does not match original", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_equals(CIDv1)", "", 1);
        }
        peer_id_destroy(&pid);
        peer_id_destroy(&pid_from_cid);
    }

    /***********************
     * Test 4: Test peer_id_equals with different peer IDs
     ***********************/
    {
        size_t pubkey_len = 0;
        uint8_t *pubkey = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pubkey_len);
        if (!pubkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 public hex to bytes (equals test)\n");
            exit(EXIT_FAILURE);
        }
        peer_id_t pid1, pid2;
        pid1.bytes = pid2.bytes = NULL;
        pid1.size = pid2.size = 0;
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid1);
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid2);
        free(pubkey);

        if (peer_id_equals(&pid1, &pid2) != 1)
        {
            print_standard("peer_id_equals(same IDs)", "Peer IDs should be equal", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_equals(same IDs)", "", 1);
        }

        /* Modify one byte in pid2 and ensure they are no longer equal */
        if (pid2.size > 0)
        {
            pid2.bytes[0] ^= 0xFF;
        }
        if (peer_id_equals(&pid1, &pid2) != 0)
        {
            print_standard("peer_id_equals(different IDs)", "Peer IDs should not be equal", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_equals(different IDs)", "", 1);
        }
        peer_id_destroy(&pid1);
        peer_id_destroy(&pid2);
    }

    /***********************
     * Test 5: Test peer_id_destroy
     ***********************/
    {
        size_t pubkey_len = 0;
        uint8_t *pubkey = hex_to_bytes(SECP256K1_PUBLIC_HEX, &pubkey_len);
        if (!pubkey)
        {
            fprintf(stderr, "Failed to convert secp256k1 public hex to bytes (destroy test)\n");
            exit(EXIT_FAILURE);
        }
        peer_id_t pid;
        pid.bytes = NULL;
        pid.size = 0;
        err = peer_id_create_from_public_key(pubkey, pubkey_len, &pid);
        free(pubkey);
        peer_id_destroy(&pid);
        if (pid.bytes != NULL || pid.size != 0)
        {
            print_standard("peer_id_destroy()", "Peer ID not properly destroyed", 0);
            failures++;
        }
        else
        {
            print_standard("peer_id_destroy()", "", 1);
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