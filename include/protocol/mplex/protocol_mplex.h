#ifndef PROTOCOL_MPLEX_H
#define PROTOCOL_MPLEX_H

#ifdef __cplusplus
extern "C" {
#endif

#include "protocol/mplex/protocol_mplex_queue.h"
#include "protocol/mplex/protocol_mplex_stream_array.h"
#include "transport/connection.h"
#include "transport/muxer.h"
#include <stdint.h>
#include <stdatomic.h>

/**
 * @file protocol_mplex.h
 * @brief API for the mplex stream multiplexer.
 */


/**
 * @brief Canonical protocol id.
 */
#define LIBP2P_MPLEX_PROTO_ID "/mplex/6.7.0"

/**
 * @brief Maximum message size (1 MiB as per spec).
 */
#define MPLEX_MAX_MSG_SIZE (1024 * 1024)

/**
 * @brief Maximum stream identifier (2^60).
 */
#define MPLEX_MAX_STREAM_ID ((uint64_t)1 << 60)

/**
 * @brief Maximum receive buffer size (4 * MPLEX_MAX_MSG_SIZE).
 */
#define MPLEX_MAX_RECV_BUF (4 * MPLEX_MAX_MSG_SIZE)

/**
 * @brief Error codes returned by mplex operations.
 */
typedef enum
{
    LIBP2P_MPLEX_OK = 0,
    LIBP2P_MPLEX_ERR_NULL_PTR = -1,
    LIBP2P_MPLEX_ERR_HANDSHAKE = -2,
    LIBP2P_MPLEX_ERR_INTERNAL = -3,
    LIBP2P_MPLEX_ERR_PROTO_MAL = -4,
    LIBP2P_MPLEX_ERR_TIMEOUT = -5,
    LIBP2P_MPLEX_ERR_EOF = -6,
    LIBP2P_MPLEX_ERR_AGAIN = -7,
    LIBP2P_MPLEX_ERR_RESET = -8
} libp2p_mplex_err_t;

/**
 * @brief Flags describing the type of an mplex frame.
 */
typedef enum
{
    LIBP2P_MPLEX_NEW_STREAM = 0,
    LIBP2P_MPLEX_MSG_RECEIVER = 1,
    LIBP2P_MPLEX_MSG_INITIATOR = 2,
    LIBP2P_MPLEX_CLOSE_RECEIVER = 3,
    LIBP2P_MPLEX_CLOSE_INITIATOR = 4,
    LIBP2P_MPLEX_RESET_RECEIVER = 5,
    LIBP2P_MPLEX_RESET_INITIATOR = 6
} libp2p_mplex_flag_t;

/**
 * @brief Frame exchanged over the mplex connection.
 */
typedef struct
{
    uint64_t id;              /**< Stream identifier.          */
    libp2p_mplex_flag_t flag; /**< Frame flag.                  */
    uint8_t *data;            /**< Payload bytes (may be NULL). */
    size_t data_len;          /**< Length of @p data.           */
} libp2p_mplex_frame_t;

/**
 * @brief State for an individual mplex stream.
 */
typedef struct libp2p_mplex_stream
{
    uint64_t id;         /**< Stream identifier.            */
    int initiator;       /**< Non-zero if this side opened it. */
    uint8_t *name;       /**< Optional stream name.         */
    size_t name_len;     /**< Length of @p name.            */
    int local_closed;    /**< Local side closed.            */
    int remote_closed;   /**< Remote side closed.           */
    int reset;           /**< Stream was reset.             */
    uint8_t *buf;        /**< Data buffer.                  */
    size_t buf_len;      /**< Size of @p buf.               */
    size_t buf_pos;      /**< Current read position.        */
} libp2p_mplex_stream_t;

/**
 * @brief Context used by the mplex multiplexer.
 */
typedef struct
{
    libp2p_conn_t *conn;              /**< Underlying connection.        */
    mplex_stream_array_t streams;        /**< Active streams list.          */
    uint64_t next_stream_id;          /**< Next stream id to assign.     */
    mplex_stream_queue_t incoming;    /**< Queue of incoming streams.    */
    atomic_bool stop;                 /**< Stop processing flag.         */
    pthread_mutex_t mtx;              /**< Protects context state.       */
} libp2p_mplex_ctx_t;

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

/**
 * @brief Create a new muxer implementation using mplex.
 *
 * @return Newly allocated muxer object.
 */
libp2p_muxer_t *libp2p_mplex_new(void);

/**
 * @brief Send a frame over the raw connection.
 *
 * @param conn Connection to write to.
 * @param fr   Frame to send.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_send_frame(libp2p_conn_t *conn, const libp2p_mplex_frame_t *fr);

/**
 * @brief Read the next frame from the connection.
 *
 * @param conn Connection to read from.
 * @param out  Output frame structure.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_read_frame(libp2p_conn_t *conn, libp2p_mplex_frame_t *out);

/**
 * @brief Free resources associated with a frame.
 *
 * @param fr Frame to free.
 */
void libp2p_mplex_frame_free(libp2p_mplex_frame_t *fr);

/**
 * @brief Send an open-stream frame.
 *
 * @param conn     Connection to use.
 * @param id       Stream identifier.
 * @param name     Optional stream name.
 * @param name_len Length of @p name.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_open_stream(libp2p_conn_t *conn, uint64_t id, const uint8_t *name, size_t name_len);

/**
 * @brief Send application data on a stream.
 *
 * @param conn       Connection to use.
 * @param id         Stream identifier.
 * @param initiator  Non-zero if sending from initiator side.
 * @param data       Data buffer.
 * @param data_len   Length of @p data.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_send_msg(libp2p_conn_t *conn, uint64_t id, int initiator, const uint8_t *data, size_t data_len);

/**
 * @brief Send a close-stream frame.
 *
 * @param conn      Connection to use.
 * @param id        Stream identifier.
 * @param initiator Non-zero if closing initiator side.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_close_stream(libp2p_conn_t *conn, uint64_t id, int initiator);

/**
 * @brief Send a reset-stream frame.
 *
 * @param conn      Connection to use.
 * @param id        Stream identifier.
 * @param initiator Non-zero if resetting initiator side.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_reset_stream(libp2p_conn_t *conn, uint64_t id, int initiator);

/**
 * @brief Allocate a new mplex context for a connection.
 *
 * @param conn Raw connection.
 * @return Newly allocated context or NULL on error.
 */
libp2p_mplex_ctx_t *libp2p_mplex_ctx_new(libp2p_conn_t *conn);

/**
 * @brief Free an mplex context and all associated resources.
 *
 * @param ctx Context to free.
 */
void libp2p_mplex_ctx_free(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Open a new stream within a context.
 *
 * @param ctx      Mplex context.
 * @param name     Optional stream name.
 * @param name_len Length of @p name.
 * @param out_id   Assigned stream identifier.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_stream_open(libp2p_mplex_ctx_t *ctx, const uint8_t *name, size_t name_len, uint64_t *out_id);

/**
 * @brief Send data on an established stream.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Non-zero if sending from initiator side.
 * @param data      Data buffer.
 * @param data_len  Length of @p data.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_stream_send(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator, const uint8_t *data, size_t data_len);

/**
 * @brief Close a stream gracefully.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Non-zero if closing initiator side.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_stream_close(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator);

/**
 * @brief Reset a stream abruptly.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Non-zero if resetting initiator side.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_stream_reset(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator);

/**
 * @brief Handle an incoming frame within a context.
 *
 * @param ctx Mplex context.
 * @param fr  Frame to dispatch.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_dispatch_frame(libp2p_mplex_ctx_t *ctx, const libp2p_mplex_frame_t *fr);

/**
 * @brief Receive data from a stream.
 *
 * @param ctx       Mplex context.
 * @param id        Stream identifier.
 * @param initiator Non-zero if reading initiator side.
 * @param buf       Buffer for received data.
 * @param max_len   Maximum bytes to read.
 * @param out_len   Number of bytes actually read.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_stream_recv(libp2p_mplex_ctx_t *ctx, uint64_t id, int initiator, uint8_t *buf, size_t max_len, size_t *out_len);

/**
 * @brief Accept the next incoming stream, if any.
 *
 * @param ctx Mplex context.
 * @param out Returned stream pointer on success.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_accept_stream(libp2p_mplex_ctx_t *ctx, libp2p_mplex_stream_t **out);

/**
 * @brief Process a single frame from the connection.
 *
 * @param ctx Mplex context.
 * @return Error code.
 */
libp2p_mplex_err_t libp2p_mplex_process_one(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Signal the processing loop to stop.
 *
 * @param ctx Mplex context.
 */
void libp2p_mplex_stop(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Run the processing loop until stopped.
 *
 * @param ctx Mplex context.
 * @return Error code from processing.
 */
libp2p_mplex_err_t libp2p_mplex_process_loop(libp2p_mplex_ctx_t *ctx);

/**
 * @brief Send a message with a length prefix.
 *
 * @param mx Mplex context.
 * @param stream_id Stream identifier.
 * @param message Message to send.
 * @param initiator Non-zero if sending from initiator side.
 * @return 0 on success or negative on error.
 */
int send_length_prefixed_message(libp2p_mplex_ctx_t *mx, uint64_t stream_id,
                                 const char *message, int initiator);

/**
 * @brief Receive a message with a length prefix.
 *
 * @param mx Mplex context.
 * @param stream_id Stream identifier.
 * @param initiator Non-zero if reading from initiator side.
 * @param buffer Buffer for message.
 * @param max_len Maximum length of message.
 * @return 0 on success or negative on error.
 */
int recv_length_prefixed_message(libp2p_mplex_ctx_t *mx, uint64_t stream_id,
                                 int initiator, char *buffer, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_MPLEX_H */
