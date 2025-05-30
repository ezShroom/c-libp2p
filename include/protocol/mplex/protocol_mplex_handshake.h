#ifndef PROTOCOL_MPLEX_HANDSHAKE_H
#define PROTOCOL_MPLEX_HANDSHAKE_H

#include "protocol/mplex/protocol_mplex.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Perform the outbound side of the mplex handshake.
 *
 * @param conn       Connection to negotiate on.
 * @param timeout_ms 0 → no timeout for the handshake.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_negotiate_outbound(libp2p_conn_t *conn, uint64_t timeout_ms);

/**
 * @brief Perform the inbound side of the mplex handshake.
 *
 * @param conn       Connection to negotiate on.
 * @param timeout_ms 0 → no timeout for the handshake.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_negotiate_inbound(libp2p_conn_t *conn, uint64_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_MPLEX_HANDSHAKE_H */
