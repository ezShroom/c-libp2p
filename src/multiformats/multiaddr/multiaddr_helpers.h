#ifndef LIBP2P_MULTIADDR_HELPERS_H
#define LIBP2P_MULTIADDR_HELPERS_H

#include "multiformats/multiaddr/types.h"

/**
 * @brief Duplicates the given string.
 *
 * @param s Pointer to the null-terminated string to duplicate.
 * @return A pointer to the newly allocated duplicate string.
 */
char *libp2p_duplicate_string(const char *s);

/**
 * @brief Creates a deep copy of the given Multiaddr structure.
 *
 * @param addr Pointer to the Multiaddr to copy.
 * @return Pointer to the newly allocated copy.
 */
Multiaddr *libp2p_multiaddr_copy(const Multiaddr *addr);

#endif // LIBP2P_MULTIADDR_HELPERS_H
