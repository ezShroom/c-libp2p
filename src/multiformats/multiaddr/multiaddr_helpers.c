#include <stdlib.h>
#include <string.h>
#include "multiaddr_helpers.h"

char *libp2p_duplicate_string(const char *s)
{
    if (s == NULL)
        return NULL;
    char *dup = malloc(strlen(s) + 1);
    if (dup)
    {
        strcpy(dup, s);
    }
    return dup;
}

Multiaddr *libp2p_multiaddr_copy(const Multiaddr *addr)
{
    if (addr == NULL)
        return NULL;
    Multiaddr *copy = malloc(sizeof(Multiaddr));
    if (!copy)
        return NULL;
    copy->component_count = addr->component_count;
    if (copy->component_count > 0)
    {
        copy->components = malloc(copy->component_count * sizeof(MultiaddrComponent));
        if (!copy->components)
        {
            free(copy);
            return NULL;
        }
        for (size_t i = 0; i < copy->component_count; i++)
        {
            copy->components[i].protocol = libp2p_duplicate_string(addr->components[i].protocol);
            copy->components[i].value = (addr->components[i].value)
                                            ? libp2p_duplicate_string(addr->components[i].value)
                                            : NULL;
        }
    }
    else
    {
        copy->components = NULL;
    }
    return copy;
}
