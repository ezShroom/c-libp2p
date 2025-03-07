#ifndef LIBP2P_MULTIADDR_H
#define LIBP2P_MULTIADDR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "types.h"

/**
 * @brief Parses a multiaddr string into a Multiaddr structure.
 *
 * @param addr A multiaddr string (e.g. "/ip4/198.51.100/tcp/1234").
 * @return Pointer to a new Multiaddr structure on success, or NULL on failure.
 */
Multiaddr *libp2p_multiaddr_parse(const char *addr);

/**
 * @brief Converts a Multiaddr structure back to its string representation.
 *
 * @param addr Pointer to a Multiaddr structure.
 * @return A newly allocated string representing the multiaddr. Caller must free() it.
 */
char *libp2p_multiaddr_to_string(const Multiaddr *addr);

/**
 * @brief Encapsulates an inner multiaddr within an outer multiaddr.
 *
 * @param outer Pointer to the outer Multiaddr.
 * @param inner Pointer to the inner Multiaddr to encapsulate.
 * @return A new Multiaddr representing the encapsulation.
 */
Multiaddr *libp2p_multiaddr_encapsulate(const Multiaddr *outer, const Multiaddr *inner);

/**
 * @brief Decapsulates an inner multiaddr from a given multiaddr.
 *
 * @param addr Pointer to the original Multiaddr.
 * @param inner Pointer to the Multiaddr to decapsulate.
 * @return A new Multiaddr with the last occurrence of inner removed.
 */
Multiaddr *libp2p_multiaddr_decapsulate(const Multiaddr *addr, const Multiaddr *inner);

/**
 * @brief Frees a Multiaddr structure and its components.
 *
 * @param addr Pointer to the Multiaddr to free.
 */
void libp2p_multiaddr_free(Multiaddr *addr);

#ifdef __cplusplus
}
#endif

#endif // LIBP2P_MULTIADDR_H
