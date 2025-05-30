#ifndef PROTOCOL_MPLEX_CODEC_H
#define PROTOCOL_MPLEX_CODEC_H

#include "protocol/mplex/protocol_mplex.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Encode and send a single mplex frame over the connection.
 *
 * @param conn Connection to send on.
 * @param fr   Frame to encode and transmit.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
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

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_MPLEX_CODEC_H */
