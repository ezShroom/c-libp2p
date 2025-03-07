#ifndef LIBP2P_MULTIADDR_TYPES_H
#define LIBP2P_MULTIADDR_TYPES_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>

    /**
     * @brief Represents a single multiaddr component.
     *
     * Each component has a protocol (e.g. "ip4", "tcp", "p2p") and an optional
     * value (such as an IP address, port, or peer id).
     */
    typedef struct
    {
        char *protocol;
        char *value; // May be NULL if the protocol does not require an argument.
    } MultiaddrComponent;

    /**
     * @brief Represents a multiaddr as a sequence of components.
     */
    typedef struct
    {
        MultiaddrComponent *components;
        size_t component_count;
    } Multiaddr;

#ifdef __cplusplus
}
#endif

#endif // LIBP2P_MULTIADDR_TYPES_H
