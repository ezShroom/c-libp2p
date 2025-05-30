#include "protocol/mplex/protocol_mplex_handshake.h"
#include "protocol/multiselect/protocol_multiselect.h"

/**
 * @brief Perform outbound protocol negotiation for mplex.
 *
 * Attempts to select the mplex protocol on an already established connection
 * by acting as the dialing side of the multiselect handshake.
 *
 * @param conn       Connection to negotiate on.
 * @param timeout_ms Maximum time in milliseconds to wait for the handshake.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
libp2p_mplex_err_t libp2p_mplex_negotiate_outbound(libp2p_conn_t *conn, uint64_t timeout_ms)
{
    if (!conn)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    const char *proposals[] = {LIBP2P_MPLEX_PROTO_ID, NULL};
    libp2p_multiselect_err_t rc = libp2p_multiselect_dial(conn, proposals, timeout_ms, NULL);
    if (rc != LIBP2P_MULTISELECT_OK)
        return LIBP2P_MPLEX_ERR_HANDSHAKE;
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Perform inbound protocol negotiation for mplex.
 *
 * Waits for the remote side to propose the mplex protocol and completes the
 * multiselect handshake as the listener.
 *
 * @param conn       Connection to negotiate on.
 * @param timeout_ms Maximum time in milliseconds to wait for the handshake.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
libp2p_mplex_err_t libp2p_mplex_negotiate_inbound(libp2p_conn_t *conn, uint64_t timeout_ms)
{
    if (!conn)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    const char *supported[] = {LIBP2P_MPLEX_PROTO_ID, NULL};
    libp2p_multiselect_config_t cfg = libp2p_multiselect_config_default();
    cfg.handshake_timeout_ms = timeout_ms;
    libp2p_multiselect_err_t rc = libp2p_multiselect_listen(conn, supported, &cfg, NULL);
    if (rc != LIBP2P_MULTISELECT_OK)
        return LIBP2P_MPLEX_ERR_HANDSHAKE;
    return LIBP2P_MPLEX_OK;
}
