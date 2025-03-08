#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "multiformats/multiaddr/multiaddr.h"

int main(void) {
    int errors = 0;

    // Test 1: Parse "/ip4/198.51.100/tcp/1234"
    const char *addr_str = "/ip4/198.51.100/tcp/1234";
    Multiaddr *addr = libp2p_multiaddr_parse(addr_str);
    if (!addr) {
        fprintf(stderr, "Test 1: Failed to parse multiaddr string: %s\n", addr_str);
        errors++;
    } else {
        if (addr->component_count != 2) {
            fprintf(stderr, "Test 1: Expected 2 components, got %zu\n", addr->component_count);
            errors++;
        } else {
            if (strcmp(addr->components[0].protocol, "ip4") != 0 ||
                strcmp(addr->components[0].value, "198.51.100") != 0) {
                fprintf(stderr, "Test 1: Component 0 mismatch: expected (ip4,198.51.100) got (%s,%s)\n",
                        addr->components[0].protocol,
                        addr->components[0].value ? addr->components[0].value : "NULL");
                errors++;
            }
            if (strcmp(addr->components[1].protocol, "tcp") != 0 ||
                strcmp(addr->components[1].value, "1234") != 0) {
                fprintf(stderr, "Test 1: Component 1 mismatch: expected (tcp,1234) got (%s,%s)\n",
                        addr->components[1].protocol,
                        addr->components[1].value ? addr->components[1].value : "NULL");
                errors++;
            }
        }
    }

    // Test 2: Convert parsed multiaddr back to string
    char *str_from_addr = libp2p_multiaddr_to_string(addr);
    if (!str_from_addr) {
        fprintf(stderr, "Test 2: Failed to convert multiaddr to string\n");
        errors++;
    } else {
        if (strcmp(str_from_addr, addr_str) != 0) {
            fprintf(stderr, "Test 2: Converted string '%s' does not match expected '%s'\n", str_from_addr, addr_str);
            errors++;
        }
        free(str_from_addr);
    }

    // Test 3: Encapsulation: encapsulate "/ws" into "/ip4/198.51.100/tcp/1234" to produce "/ip4/198.51.100/tcp/1234/ws"
    const char *inner_str = "/ws";
    Multiaddr *inner = libp2p_multiaddr_parse(inner_str);
    if (!inner) {
        fprintf(stderr, "Test 3: Failed to parse inner multiaddr: %s\n", inner_str);
        errors++;
    } else {
        Multiaddr *encapsulated = libp2p_multiaddr_encapsulate(addr, inner);
        if (!encapsulated) {
            fprintf(stderr, "Test 3: Encapsulation failed\n");
            errors++;
        } else {
            char *encapsulated_str = libp2p_multiaddr_to_string(encapsulated);
            const char *expected_encapsulated_str = "/ip4/198.51.100/tcp/1234/ws";
            if (strcmp(encapsulated_str, expected_encapsulated_str) != 0) {
                fprintf(stderr, "Test 3: Encapsulated string '%s' does not match expected '%s'\n", encapsulated_str, expected_encapsulated_str);
                errors++;
            }
            free(encapsulated_str);
            libp2p_multiaddr_free(encapsulated);
        }
    }
    libp2p_multiaddr_free(inner);

    // Test 4: Decapsulation: decapsulate "/ws" from "/ip4/198.51.100/tcp/1234/ws" to produce "/ip4/198.51.100/tcp/1234"
    inner = libp2p_multiaddr_parse("/ws");
    Multiaddr *encapsulated = libp2p_multiaddr_encapsulate(addr, inner);
    Multiaddr *decapsulated = libp2p_multiaddr_decapsulate(encapsulated, inner);
    char *decapsulated_str = libp2p_multiaddr_to_string(decapsulated);
    if (strcmp(decapsulated_str, addr_str) != 0) {
        fprintf(stderr, "Test 4: Decapsulated string '%s' does not match expected '%s'\n", decapsulated_str, addr_str);
        errors++;
    }
    free(decapsulated_str);
    libp2p_multiaddr_free(decapsulated);
    libp2p_multiaddr_free(encapsulated);
    libp2p_multiaddr_free(inner);

    // Cleanup
    libp2p_multiaddr_free(addr);

    if (errors == 0) {
        printf("All tests passed successfully.\n");
    } else {
        printf("There were %d test errors.\n", errors);
    }

    return errors;
}
