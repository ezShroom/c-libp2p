#ifndef LIBP2P_PROTOCOL_HANDLER_H
#define LIBP2P_PROTOCOL_HANDLER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "peer_id/peer_id.h"
#include "protocol/mplex/protocol_mplex.h"
#include "transport/connection.h"
#include "transport/upgrader.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @file protocol_handler.h
 * @brief High-level protocol handler system for libp2p.
 *
 * This module provides automatic stream management, multiselect negotiation,
 * and protocol dispatch for libp2p applications. Protocol handlers are
 * registered once and automatically handle incoming streams.
 */

/** @brief Maximum length for protocol IDs */
#define LIBP2P_PROTOCOL_ID_MAX_LEN 256

/** @brief Protocol handler error codes */
typedef enum
{
    LIBP2P_PROTOCOL_HANDLER_OK = 0,
    LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR = -1,
    LIBP2P_PROTOCOL_HANDLER_ERR_PROTOCOL_EXISTS = -2,
    LIBP2P_PROTOCOL_HANDLER_ERR_PROTOCOL_NOT_FOUND = -3,
    LIBP2P_PROTOCOL_HANDLER_ERR_MULTISELECT = -4,
    LIBP2P_PROTOCOL_HANDLER_ERR_STREAM = -5,
    LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL = -6
} libp2p_protocol_handler_err_t;

/** @brief Represents a logical stream for a protocol */
struct libp2p_stream
{
    libp2p_uconn_t *uconn; /**< Underlying upgraded connection */
    uint64_t stream_id;    /**< Stream identifier in muxer */
    int initiator;         /**< Non-zero if this side opened the stream */
    char *protocol_id;     /**< Negotiated protocol ID */
    void *ctx;             /**< Internal context for stream management */
};

/**
 * @brief Protocol handler callback function.
 *
 * This function is called when a stream for the registered protocol
 * is opened (either inbound or outbound).
 *
 * @param stream The protocol stream (automatically negotiated)
 * @param user_data User-provided context data
 * @return 0 on success, negative on error
 */
typedef int (*libp2p_protocol_handler_t)(libp2p_stream_t *stream, void *user_data);

/** @brief Protocol handler registry entry */
typedef struct libp2p_protocol_handler_entry
{
    char protocol_id[LIBP2P_PROTOCOL_ID_MAX_LEN];
    libp2p_protocol_handler_t handler;
    void *user_data;
    struct libp2p_protocol_handler_entry *next;
} libp2p_protocol_handler_entry_t;

/** @brief Protocol handler registry */
typedef struct
{
    libp2p_protocol_handler_entry_t *handlers;
    pthread_mutex_t mutex;
} libp2p_protocol_handler_registry_t;

/** @brief Protocol handler context for managing streams */
typedef struct
{
    libp2p_protocol_handler_registry_t *registry;
    libp2p_uconn_t *uconn;
    void *muxer_ctx;       /**< Muxer-specific context (e.g., libp2p_mplex_ctx_t *) */
    void *handler_context; /**< Event-driven handler context for stream lifecycle management */
    pthread_t handler_thread;
    int stop_flag;
    pthread_mutex_t mutex;
} libp2p_protocol_handler_ctx_t;

/* ===== Registry Management ===== */

/**
 * @brief Create a new protocol handler registry.
 *
 * @return New registry instance or NULL on error
 */
libp2p_protocol_handler_registry_t *libp2p_protocol_handler_registry_new(void);

/**
 * @brief Free a protocol handler registry.
 *
 * @param registry Registry to free (may be NULL)
 */
void libp2p_protocol_handler_registry_free(libp2p_protocol_handler_registry_t *registry);

/**
 * @brief Register a protocol handler.
 *
 * Registers a callback function to handle streams for a specific protocol.
 * When a stream is opened with multiselect negotiation for this protocol,
 * the handler will be called automatically.
 *
 * @param registry Protocol handler registry
 * @param protocol_id Protocol identifier (e.g., "/ipfs/id/1.0.0")
 * @param handler Callback function to handle streams
 * @param user_data User context passed to handler
 * @return LIBP2P_PROTOCOL_HANDLER_OK or error code
 */
int libp2p_register_protocol_handler(libp2p_protocol_handler_registry_t *registry, const char *protocol_id, libp2p_protocol_handler_t handler,
                                     void *user_data);

/**
 * @brief Unregister a protocol handler.
 *
 * @param registry Protocol handler registry
 * @param protocol_id Protocol identifier to unregister
 * @return LIBP2P_PROTOCOL_HANDLER_OK or error code
 */
int libp2p_unregister_protocol_handler(libp2p_protocol_handler_registry_t *registry, const char *protocol_id);

/* ===== Stream Management ===== */

/**
 * @brief Create a protocol handler context for an upgraded connection.
 *
 * This sets up automatic stream handling for the connection using the
 * provided protocol registry.
 *
 * @param registry Protocol handler registry
 * @param uconn Upgraded connection to manage
 * @return Protocol handler context or NULL on error
 */
libp2p_protocol_handler_ctx_t *libp2p_protocol_handler_ctx_new(libp2p_protocol_handler_registry_t *registry, libp2p_uconn_t *uconn);

/**
 * @brief Start the protocol handler for a connection.
 *
 * This starts a background thread that listens for incoming streams
 * and dispatches them to registered protocol handlers.
 *
 * @param ctx Protocol handler context
 * @return LIBP2P_PROTOCOL_HANDLER_OK or error code
 */
int libp2p_protocol_handler_start(libp2p_protocol_handler_ctx_t *ctx);

/**
 * @brief Stop the protocol handler.
 *
 * @param ctx Protocol handler context
 */
void libp2p_protocol_handler_stop(libp2p_protocol_handler_ctx_t *ctx);

/**
 * @brief Free a protocol handler context.
 *
 * @param ctx Context to free (may be NULL)
 */
void libp2p_protocol_handler_ctx_free(libp2p_protocol_handler_ctx_t *ctx);

/* ===== Stream Operations ===== */

/**
 * @brief Open a new outbound stream with protocol negotiation.
 *
 * This function opens a new stream to the remote peer and performs
 * multiselect negotiation for the specified protocol.
 *
 * @param uconn Upgraded connection
 * @param protocol_id Protocol to negotiate
 * @param stream Output stream on success
 * @return LIBP2P_PROTOCOL_HANDLER_OK or error code
 */
int libp2p_protocol_open_stream(libp2p_uconn_t *uconn, const char *protocol_id, libp2p_stream_t **stream);

/**
 * @brief Open a protocol stream using existing mplex context.
 *
 * This function opens a new stream using an existing mplex context to avoid
 * conflicts when multiple mplex contexts try to use the same connection.
 *
 * @param mx Existing mplex context to reuse
 * @param uconn Upgraded connection
 * @param protocol_id Protocol to negotiate
 * @param stream Output stream on success
 * @return LIBP2P_PROTOCOL_HANDLER_OK or error code
 */
int libp2p_protocol_open_stream_with_context(libp2p_mplex_ctx_t *mx, libp2p_uconn_t *uconn, const char *protocol_id, libp2p_stream_t **stream);

/**
 * @brief Send data on a protocol stream.
 *
 * @param stream Protocol stream
 * @param data Data to send
 * @param len Length of data
 * @return Number of bytes sent or negative error code
 */
ssize_t libp2p_stream_write(libp2p_stream_t *stream, const void *data, size_t len);

/**
 * @brief Receive data from a protocol stream.
 *
 * @param stream Protocol stream
 * @param buf Buffer for received data
 * @param len Maximum bytes to receive
 * @return Number of bytes received or negative error code
 */
ssize_t libp2p_stream_read(libp2p_stream_t *stream, void *buf, size_t len);

/**
 * @brief Close a protocol stream.
 *
 * @param stream Stream to close
 */
void libp2p_stream_close(libp2p_stream_t *stream);

/**
 * @brief Free a protocol stream.
 *
 * @param stream Stream to free (may be NULL)
 */
void libp2p_stream_free(libp2p_stream_t *stream);

/**
 * @brief Get the remote peer ID for a stream.
 *
 * @param stream Protocol stream
 * @return Remote peer ID or NULL on error
 */
const peer_id_t *libp2p_stream_remote_peer(libp2p_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_HANDLER_H */
