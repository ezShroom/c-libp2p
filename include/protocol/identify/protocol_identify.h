#ifndef PROTOCOL_IDENTIFY_H
#define PROTOCOL_IDENTIFY_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "peer_id/peer_id.h"
#include "protocol/protocol_handler.h"
#include <stddef.h>
#include <stdint.h>

/** @brief Protocol ID for the identify protocol */
#define LIBP2P_IDENTIFY_PROTO_ID "/ipfs/id/1.0.0"

/** @brief Protocol ID for the identify push protocol */
#define LIBP2P_IDENTIFY_PUSH_PROTO_ID "/ipfs/id/push/1.0.0"

/**
 * @brief Structure representing an identify message.
 *
 * Contains information about a peer including its protocol version,
 * agent version, public key, listening addresses, and supported protocols.
 */
typedef struct libp2p_identify
{
    char *protocol_version;    /**< Protocol version string */
    char *agent_version;       /**< Agent version string */
    uint8_t *public_key;       /**< Peer's public key */
    size_t public_key_len;     /**< Length of public key */
    uint8_t **listen_addrs;    /**< Array of listening addresses */
    size_t *listen_addrs_lens; /**< Array of address lengths */
    size_t num_listen_addrs;   /**< Number of listening addresses */
    uint8_t *observed_addr;    /**< Observed address from remote peer */
    size_t observed_addr_len;  /**< Length of observed address */
    char **protocols;          /**< Array of supported protocol strings */
    size_t num_protocols;      /**< Number of supported protocols */
} libp2p_identify_t;

/**
 * @brief Decode an identify message from protobuf bytes.
 *
 * @param buf Input buffer containing protobuf-encoded identify message
 * @param len Length of input buffer
 * @param out_msg Output pointer to decoded identify message (caller must free)
 * @return 0 on success, negative on error
 */
int libp2p_identify_message_decode(const uint8_t *buf, size_t len, libp2p_identify_t **out_msg);

/**
 * @brief Encode an identify message to protobuf bytes.
 *
 * @param msg Input identify message to encode
 * @param out_buf Output buffer containing encoded message (caller must free)
 * @param out_len Output length of encoded buffer
 * @return 0 on success, negative on error
 */
int libp2p_identify_message_encode(const libp2p_identify_t *msg, uint8_t **out_buf, size_t *out_len);

/**
 * @brief Free an identify message.
 *
 * @param msg The identify message to free.
 */
void libp2p_identify_free(libp2p_identify_t *msg);

/**
 * @brief Callback function for handling identify requests.
 *
 * This function should populate the identify response with local peer information.
 *
 * @param local_peer_id Local peer ID
 * @param response Output identify message to populate
 * @param user_data User-provided context
 * @return 0 on success, negative on error
 */
typedef int (*libp2p_identify_request_handler_t)(const peer_id_t *local_peer_id, libp2p_identify_t *response, void *user_data);

/**
 * @brief Callback function for handling identify responses.
 *
 * This function is called when an identify response is received from a peer.
 *
 * @param remote_peer_id Remote peer ID
 * @param response Received identify message
 * @param user_data User-provided context
 * @return 0 on success, negative on error
 */
typedef int (*libp2p_identify_response_handler_t)(const peer_id_t *remote_peer_id, const libp2p_identify_t *response, void *user_data);

/**
 * @brief Register the identify protocol handler.
 *
 * This sets up automatic handling of incoming identify requests using the
 * provided callback function. The handler will automatically perform
 * multiselect negotiation and message encoding/decoding.
 *
 * @param registry Protocol handler registry
 * @param request_handler Callback to handle identify requests
 * @param user_data User context passed to handler
 * @return 0 on success, negative on error
 */
int libp2p_identify_register_handler(libp2p_protocol_handler_registry_t *registry, libp2p_identify_request_handler_t request_handler,
                                     void *user_data);

/**
 * @brief Send an identify request using an existing protocol handler context.
 *
 * This function uses the existing mplex context from the protocol handler
 * to open a new stream for the identify protocol.
 *
 * @param handler_ctx Protocol handler context with existing mplex session
 * @param response_handler Callback for handling the response
 * @param user_data User context passed to response handler
 * @return 0 on success, negative on error
 */
int libp2p_identify_send_request_with_context(libp2p_protocol_handler_ctx_t *handler_ctx, libp2p_identify_response_handler_t response_handler,
                                              void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_IDENTIFY_H */
