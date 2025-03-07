#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "multiaddr/multiaddr.h"
#include "multiaddr/multiaddr_helpers.h"

Multiaddr *libp2p_multiaddr_parse(const char *addr)
{
    if (addr == NULL)
        return NULL;

    // Ensure the address starts with '/'
    if (addr[0] != '/')
    {
        return NULL;
    }

    char *addr_copy = libp2p_duplicate_string(addr);
    if (!addr_copy)
        return NULL;

    Multiaddr *ma = malloc(sizeof(Multiaddr));
    if (!ma)
    {
        free(addr_copy);
        return NULL;
    }
    ma->components = NULL;
    ma->component_count = 0;

    char *saveptr;
    char *token = strtok_r(addr_copy, "/", &saveptr);

    size_t capacity = 4;
    ma->components = malloc(capacity * sizeof(MultiaddrComponent));
    if (!ma->components)
    {
        free(addr_copy);
        free(ma);
        return NULL;
    }

    while (token != NULL)
    {
        MultiaddrComponent comp;
        comp.protocol = libp2p_duplicate_string(token);
        comp.value = NULL;

        // Peek at the next token as the value (if present)
        char *next = strtok_r(NULL, "/", &saveptr);
        if (next != NULL)
        {
            comp.value = libp2p_duplicate_string(next);
        }

        if (ma->component_count >= capacity)
        {
            capacity *= 2;
            MultiaddrComponent *temp = realloc(ma->components, capacity * sizeof(MultiaddrComponent));
            if (!temp)
            {
                libp2p_multiaddr_free(ma);
                free(addr_copy);
                return NULL;
            }
            ma->components = temp;
        }
        ma->components[ma->component_count++] = comp;

        // If a value was consumed, get the next protocol token.
        if (comp.value != NULL)
        {
            token = strtok_r(NULL, "/", &saveptr);
        }
        else
        {
            token = NULL;
        }
    }

    free(addr_copy);
    return ma;
}

char *libp2p_multiaddr_to_string(const Multiaddr *addr)
{
    if (addr == NULL)
        return NULL;

    size_t length = 0;
    for (size_t i = 0; i < addr->component_count; i++)
    {
        // Each component contributes a '/' plus the protocol string.
        length += 1 + strlen(addr->components[i].protocol);
        if (addr->components[i].value)
        {
            // And if there’s a value, another '/' plus the value string.
            length += 1 + strlen(addr->components[i].value);
        }
    }
    length += 1; // Terminating null byte.

    char *result = malloc(length);
    if (!result)
        return NULL;

    result[0] = '\0';
    for (size_t i = 0; i < addr->component_count; i++)
    {
        strcat(result, "/");
        strcat(result, addr->components[i].protocol);
        if (addr->components[i].value)
        {
            strcat(result, "/");
            strcat(result, addr->components[i].value);
        }
    }

    return result;
}

Multiaddr *libp2p_multiaddr_encapsulate(const Multiaddr *outer, const Multiaddr *inner)
{
    if (outer == NULL || inner == NULL)
        return NULL;

    Multiaddr *result = malloc(sizeof(Multiaddr));
    if (!result)
        return NULL;

    result->component_count = outer->component_count + inner->component_count;
    result->components = malloc(result->component_count * sizeof(MultiaddrComponent));
    if (!result->components)
    {
        free(result);
        return NULL;
    }

    // Copy outer components.
    for (size_t i = 0; i < outer->component_count; i++)
    {
        result->components[i].protocol = libp2p_duplicate_string(outer->components[i].protocol);
        result->components[i].value = (outer->components[i].value)
                                          ? libp2p_duplicate_string(outer->components[i].value)
                                          : NULL;
    }

    // Append inner components.
    for (size_t j = 0; j < inner->component_count; j++)
    {
        size_t index = outer->component_count + j;
        result->components[index].protocol = libp2p_duplicate_string(inner->components[j].protocol);
        result->components[index].value = (inner->components[j].value)
                                              ? libp2p_duplicate_string(inner->components[j].value)
                                              : NULL;
    }

    return result;
}

Multiaddr *libp2p_multiaddr_decapsulate(const Multiaddr *addr, const Multiaddr *inner)
{
    if (addr == NULL || inner == NULL || inner->component_count == 0)
        return libp2p_multiaddr_copy(addr);

    ssize_t last_index = -1;
    for (ssize_t i = 0; i <= (ssize_t)(addr->component_count - inner->component_count); i++)
    {
        int match = 1;
        for (size_t j = 0; j < inner->component_count; j++)
        {
            MultiaddrComponent comp1 = addr->components[i + j];
            MultiaddrComponent comp2 = inner->components[j];
            if (strcmp(comp1.protocol, comp2.protocol) != 0)
            {
                match = 0;
                break;
            }
            if ((comp1.value == NULL && comp2.value != NULL) ||
                (comp1.value != NULL && comp2.value == NULL))
            {
                match = 0;
                break;
            }
            if (comp1.value && comp2.value && strcmp(comp1.value, comp2.value) != 0)
            {
                match = 0;
                break;
            }
        }
        if (match)
        {
            last_index = i;
        }
    }

    if (last_index == -1)
    {
        return libp2p_multiaddr_copy(addr);
    }

    Multiaddr *result = malloc(sizeof(Multiaddr));
    if (!result)
        return NULL;
    result->component_count = last_index;
    if (last_index > 0)
    {
        result->components = malloc(last_index * sizeof(MultiaddrComponent));
        if (!result->components)
        {
            free(result);
            return NULL;
        }
        for (size_t i = 0; i < (size_t)last_index; i++)
        {
            result->components[i].protocol = libp2p_duplicate_string(addr->components[i].protocol);
            result->components[i].value = (addr->components[i].value)
                                              ? libp2p_duplicate_string(addr->components[i].value)
                                              : NULL;
        }
    }
    else
    {
        result->components = NULL;
    }

    return result;
}

void libp2p_multiaddr_free(Multiaddr *addr)
{
    if (!addr)
        return;
    if (addr->components)
    {
        for (size_t i = 0; i < addr->component_count; i++)
        {
            free(addr->components[i].protocol);
            free(addr->components[i].value);
        }
        free(addr->components);
    }
    free(addr);
}
