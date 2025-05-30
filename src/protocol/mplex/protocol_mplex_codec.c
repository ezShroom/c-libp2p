#include "protocol/mplex/protocol_mplex_codec.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/tcp/protocol_tcp_util.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * @brief Convert a generic connection error into an mplex error code.
 *
 * @param v Error value returned from the connection layer.
 * @return Corresponding mplex error code.
 */
static inline libp2p_mplex_err_t map_conn_err(ssize_t v)
{
    switch ((libp2p_conn_err_t)v)
    {
        case LIBP2P_CONN_ERR_TIMEOUT:
            return LIBP2P_MPLEX_ERR_HANDSHAKE;
        case LIBP2P_CONN_ERR_AGAIN:
        case LIBP2P_CONN_ERR_EOF:
        case LIBP2P_CONN_ERR_CLOSED:
        case LIBP2P_CONN_ERR_INTERNAL:
        default:
            return LIBP2P_MPLEX_ERR_INTERNAL;
    }
}

/**
 * @brief Write the entire buffer to the connection with a soft timeout.
 *
 * The function retries short writes until the buffer is sent or a timeout
 * occurs.  A small sleep is inserted when the connection would block.
 *
 * @param c   Connection to write to.
 * @param buf Buffer containing data.
 * @param len Number of bytes to write.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
static libp2p_mplex_err_t conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    const uint64_t SLOW_MS = 100; // Reduced from 1000ms to 100ms for faster response
    uint64_t start = now_mono_ms();

    while (len)
    {
        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            if (now_mono_ms() - start > SLOW_MS)
                return LIBP2P_MPLEX_ERR_TIMEOUT;
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000L};
            nanosleep(&ts, NULL);
            continue;
        }
        return map_conn_err(n);
    }
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Read exactly @p len bytes from a connection.
 *
 * Repeatedly reads from the connection until the requested number of bytes has
 * been obtained or an error occurs.
 *
 * @param c   Connection to read from.
 * @param buf Destination buffer.
 * @param len Number of bytes to read.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
static libp2p_mplex_err_t conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
{
    while (len)
    {
        ssize_t n = libp2p_conn_read(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
            continue;
        return map_conn_err(n);
    }
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Encode and send a single mplex frame over the connection.
 *
 * @param conn Connection to send on.
 * @param fr   Frame to encode and transmit.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
libp2p_mplex_err_t libp2p_mplex_send_frame(libp2p_conn_t *conn, const libp2p_mplex_frame_t *fr)
{
    if (!conn || !fr)
        return LIBP2P_MPLEX_ERR_NULL_PTR;
    if (fr->data_len > MPLEX_MAX_MSG_SIZE)
        return LIBP2P_MPLEX_ERR_PROTO_MAL;

    uint8_t hdr_buf[10];
    size_t hdr_len;
    uint64_t hdr_val = (fr->id << 3) | (uint8_t)fr->flag;
    if (unsigned_varint_encode(hdr_val, hdr_buf, sizeof(hdr_buf), &hdr_len))
        return LIBP2P_MPLEX_ERR_INTERNAL;

    uint8_t len_buf[10];
    size_t len_len;
    if (unsigned_varint_encode(fr->data_len, len_buf, sizeof(len_buf), &len_len))
        return LIBP2P_MPLEX_ERR_INTERNAL;

    libp2p_mplex_err_t rc;
    rc = conn_write_all(conn, hdr_buf, hdr_len);
    if (rc)
        return rc;
    rc = conn_write_all(conn, len_buf, len_len);
    if (rc)
        return rc;
    return conn_write_all(conn, fr->data, fr->data_len);
}

/**
 * @brief Read and decode a single mplex frame from the connection.
 *
 * Allocates memory for the payload if the frame carries data. The caller is
 * responsible for freeing it using ::libp2p_mplex_frame_free.
 *
 * @param conn Connection to read from.
 * @param out  Destination for the decoded frame.
 * @return LIBP2P_MPLEX_OK on success or an error code on failure.
 */
libp2p_mplex_err_t libp2p_mplex_read_frame(libp2p_conn_t *conn, libp2p_mplex_frame_t *out)
{
    if (!conn || !out)
        return LIBP2P_MPLEX_ERR_NULL_PTR;

    uint8_t tmp[9];
    size_t read = 0;
    uint64_t val = 0;
    unsigned_varint_err_t vrc = UNSIGNED_VARINT_ERR_EMPTY_INPUT;
    for (size_t i = 0; i < sizeof(tmp); i++)
    {
        libp2p_mplex_err_t rc = conn_read_exact(conn, tmp + i, 1);
        if (rc)
            return rc;
        read++;
        size_t tmp_read = 0;
        vrc = unsigned_varint_decode(tmp, read, &val, &tmp_read);
        if (vrc == UNSIGNED_VARINT_ERR_TOO_LONG)
            continue;
        if (vrc == UNSIGNED_VARINT_OK)
            break;
        if (vrc != UNSIGNED_VARINT_ERR_EMPTY_INPUT && vrc != UNSIGNED_VARINT_ERR_TOO_LONG)
            return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    if (vrc != UNSIGNED_VARINT_OK)
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    out->flag = (libp2p_mplex_flag_t)(val & 0x07);
    out->id = val >> 3;
    if (out->id >= MPLEX_MAX_STREAM_ID)
        return LIBP2P_MPLEX_ERR_PROTO_MAL;

    read = 0;
    val = 0;
    vrc = UNSIGNED_VARINT_ERR_EMPTY_INPUT;
    for (size_t i = 0; i < sizeof(tmp); i++)
    {
        libp2p_mplex_err_t rc = conn_read_exact(conn, tmp + i, 1);
        if (rc)
            return rc;
        read++;
        size_t tmp_read = 0;
        vrc = unsigned_varint_decode(tmp, read, &val, &tmp_read);
        if (vrc == UNSIGNED_VARINT_ERR_TOO_LONG)
            continue;
        if (vrc == UNSIGNED_VARINT_OK)
            break;
        if (vrc != UNSIGNED_VARINT_ERR_EMPTY_INPUT && vrc != UNSIGNED_VARINT_ERR_TOO_LONG)
            return LIBP2P_MPLEX_ERR_PROTO_MAL;
    }
    if (vrc != UNSIGNED_VARINT_OK)
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    if (val > MPLEX_MAX_MSG_SIZE)
        return LIBP2P_MPLEX_ERR_PROTO_MAL;
    out->data_len = (size_t)val;
    out->data = NULL;
    if (out->data_len)
    {
        out->data = malloc(out->data_len);
        if (!out->data)
            return LIBP2P_MPLEX_ERR_INTERNAL;
        libp2p_mplex_err_t rc = conn_read_exact(conn, out->data, out->data_len);
        if (rc)
        {
            free(out->data);
            out->data = NULL;
            out->data_len = 0;
            return rc;
        }
    }
    return LIBP2P_MPLEX_OK;
}

/**
 * @brief Release resources associated with a frame structure.
 *
 * Frees any dynamically allocated payload and resets the structure fields.
 *
 * @param fr Frame to free.
 */
void libp2p_mplex_frame_free(libp2p_mplex_frame_t *fr)
{
    if (!fr)
        return;
    free(fr->data);
    fr->data = NULL;
    fr->data_len = 0;
}

/**
 * @brief Send a NEW_STREAM frame for the specified stream.
 *
 * @param conn     Connection to use.
 * @param id       Stream identifier.
 * @param name     Optional stream name.
 * @param name_len Length of the name buffer.
 */
libp2p_mplex_err_t libp2p_mplex_open_stream(libp2p_conn_t *conn, uint64_t id, const uint8_t *name, size_t name_len)
{
    libp2p_mplex_frame_t fr = {
        .id = id,
        .flag = LIBP2P_MPLEX_NEW_STREAM,
        .data = (uint8_t *)name,
        .data_len = name_len,
    };
    return libp2p_mplex_send_frame(conn, &fr);
}

/**
 * @brief Send a data message on the given stream.
 *
 * @param conn      Connection to send on.
 * @param id        Stream identifier.
 * @param initiator Non-zero if the sender is the stream initiator.
 * @param data      Message payload.
 * @param data_len  Size of the payload in bytes.
 */
libp2p_mplex_err_t libp2p_mplex_send_msg(libp2p_conn_t *conn, uint64_t id, int initiator, const uint8_t *data, size_t data_len)
{
    libp2p_mplex_frame_t fr = {
        .id = id,
        .flag = initiator ? LIBP2P_MPLEX_MSG_INITIATOR : LIBP2P_MPLEX_MSG_RECEIVER,
        .data = (uint8_t *)data,
        .data_len = data_len,
    };
    return libp2p_mplex_send_frame(conn, &fr);
}

/**
 * @brief Send a CLOSE frame for the specified stream direction.
 *
 * @param conn      Connection to use.
 * @param id        Stream identifier.
 * @param initiator Indicates which side is closing.
 */
libp2p_mplex_err_t libp2p_mplex_close_stream(libp2p_conn_t *conn, uint64_t id, int initiator)
{
    libp2p_mplex_frame_t fr = {
        .id = id,
        .flag = initiator ? LIBP2P_MPLEX_CLOSE_INITIATOR : LIBP2P_MPLEX_CLOSE_RECEIVER,
        .data = NULL,
        .data_len = 0,
    };
    return libp2p_mplex_send_frame(conn, &fr);
}

/**
 * @brief Send a RESET frame for the specified stream.
 *
 * @param conn      Connection to use.
 * @param id        Stream identifier.
 * @param initiator Indicates which side triggers the reset.
 */
libp2p_mplex_err_t libp2p_mplex_reset_stream(libp2p_conn_t *conn, uint64_t id, int initiator)
{
    libp2p_mplex_frame_t fr = {
        .id = id,
        .flag = initiator ? LIBP2P_MPLEX_RESET_INITIATOR : LIBP2P_MPLEX_RESET_RECEIVER,
        .data = NULL,
        .data_len = 0,
    };
    return libp2p_mplex_send_frame(conn, &fr);
}
