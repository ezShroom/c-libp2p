#include "protocol/protocol_handler.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "protocol/ping/protocol_ping.h"
#include "protocol/yamux/protocol_yamux.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Forward declaration */
static libp2p_yamux_err_t libp2p_yamux_process_one_nonblocking(libp2p_yamux_ctx_t *ctx);

/* ===== Muxer Detection Helper ===== */

/**
 * @brief Detect which muxer type is being used based on the negotiated muxer.
 */
typedef enum
{
    MUXER_TYPE_MPLEX,
    MUXER_TYPE_YAMUX,
    MUXER_TYPE_UNKNOWN
} muxer_type_t;

static muxer_type_t detect_muxer_type(const libp2p_muxer_t *muxer)
{
    if (!muxer)
        return MUXER_TYPE_UNKNOWN;

    // We can distinguish muxers by checking their function pointers
    // Create temporary muxers to compare vtables
    libp2p_muxer_t *mplex_test = libp2p_mplex_new();
    libp2p_muxer_t *yamux_test = libp2p_yamux_new();

    muxer_type_t result = MUXER_TYPE_UNKNOWN;
    if (mplex_test && muxer->vt == mplex_test->vt)
    {
        result = MUXER_TYPE_MPLEX;
    }
    else if (yamux_test && muxer->vt == yamux_test->vt)
    {
        result = MUXER_TYPE_YAMUX;
    }

    if (mplex_test)
        libp2p_muxer_free(mplex_test);
    if (yamux_test)
        libp2p_muxer_free(yamux_test);

    return result;
}

/* ===== Yamux Length-Prefixed Message Functions ===== */

/**
 * @brief Send a length-prefixed message over a yamux stream.
 */
static int send_length_prefixed_message_yamux(libp2p_yamux_ctx_t *yx, uint32_t stream_id, const char *message)
{
    if (!yx || !message)
        return -1;

    size_t msg_len = strlen(message);
    fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Sending to stream %u: message_len=%zu, message='%s'\n", stream_id, msg_len, message);

    uint8_t varint_buf[10];
    size_t varint_len;
    if (unsigned_varint_encode(msg_len, varint_buf, sizeof(varint_buf), &varint_len) != UNSIGNED_VARINT_OK)
    {
        fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Failed to encode varint for length %zu\n", msg_len);
        return -1;
    }

    fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Sending varint length prefix: %zu bytes\n", varint_len);
    if (libp2p_yamux_stream_send(yx, stream_id, varint_buf, varint_len, 0) != LIBP2P_YAMUX_OK)
    {
        fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Failed to send varint length prefix\n");
        return -1;
    }

    fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Sending message content: %zu bytes\n", msg_len);
    if (libp2p_yamux_stream_send(yx, stream_id, (const uint8_t *)message, msg_len, 0) != LIBP2P_YAMUX_OK)
    {
        fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Failed to send message content\n");
        return -1;
    }

    fprintf(stderr, "[SEND_LENGTH_PREFIXED_YAMUX] Successfully sent complete message\n");
    return 0;
}

/**
 * @brief Receive a length-prefixed message from a yamux stream.
 */
static int recv_length_prefixed_message_yamux(libp2p_yamux_ctx_t *yx, uint32_t stream_id, char *buffer, size_t max_len)
{
    if (!yx || !buffer)
        return -1;

    fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Starting to receive from stream %u\n", stream_id);

    uint8_t varint_buf[10];
    size_t bytes_read = 0;
    uint64_t msg_len = 0;
    size_t varint_bytes = 0;

    // Read varint length prefix
    for (int i = 0; i < 10; i++)
    {
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Attempting to read varint byte %d\n", i);

        libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(yx, stream_id, &varint_buf[varint_bytes], 1, &bytes_read);
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] yamux_stream_recv returned: rc=%d, bytes_read=%zu\n", rc, bytes_read);

        if (rc == LIBP2P_YAMUX_ERR_AGAIN)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] No data available (ERR_AGAIN), processing frames and retrying\n");
            if (libp2p_yamux_process_one(yx) != LIBP2P_YAMUX_OK)
                usleep(1000);
            else
                usleep(1000);
            i--; /* retry same byte */
            continue;
        }
        else if (rc != LIBP2P_YAMUX_OK)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Error reading varint byte: %d\n", rc);
            return -1;
        }
        if (bytes_read == 0)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] No data available, processing frames and retrying\n");
            if (libp2p_yamux_process_one(yx) != LIBP2P_YAMUX_OK)
                usleep(1000);
            else
                usleep(1000);
            i--; /* retry same byte */
            continue;
        }
        varint_bytes++;
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Read varint byte, total bytes: %zu\n", varint_bytes);

        size_t consumed;
        if (unsigned_varint_decode(varint_buf, varint_bytes, &msg_len, &consumed) == UNSIGNED_VARINT_OK)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Decoded message length: %llu\n", (unsigned long long)msg_len);
            break;
        }
    }

    if (msg_len == 0 || msg_len >= max_len)
    {
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Invalid message length: %llu (max: %zu)\n", (unsigned long long)msg_len, max_len);
        return -1;
    }

    // Read message content
    fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Reading message content: %llu bytes\n", (unsigned long long)msg_len);
    size_t total = 0;
    while (total < msg_len)
    {
        size_t got = 0;
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Attempting to read %llu bytes (have %zu)\n", (unsigned long long)(msg_len - total), total);

        libp2p_yamux_err_t rc = libp2p_yamux_stream_recv(yx, stream_id, (uint8_t *)buffer + total, msg_len - total, &got);
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] yamux_stream_recv returned: rc=%d, got=%zu\n", rc, got);

        if (rc == LIBP2P_YAMUX_ERR_AGAIN)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] No data available (ERR_AGAIN), processing frames and retrying\n");
            if (libp2p_yamux_process_one(yx) != LIBP2P_YAMUX_OK)
                usleep(1000);
            else
                usleep(1000);
            continue;
        }
        else if (rc != LIBP2P_YAMUX_OK)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Error reading message content: %d\n", rc);
            return -1;
        }
        if (got == 0)
        {
            fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] No data available, processing frames and retrying\n");
            if (libp2p_yamux_process_one(yx) != LIBP2P_YAMUX_OK)
                usleep(1000);
            else
                usleep(1000);
            continue;
        }
        total += got;
        fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Read %zu bytes, total: %zu/%llu\n", got, total, (unsigned long long)msg_len);
    }

    buffer[msg_len] = '\0';
    fprintf(stderr, "[RECV_LENGTH_PREFIXED_YAMUX] Successfully received message: '%s'\n", buffer);
    return (int)msg_len;
}

/* ===== Generic Muxer Wrapper Structure ===== */

typedef struct
{
    muxer_type_t type;
    union
    {
        libp2p_mplex_ctx_t *mplex;
        libp2p_yamux_ctx_t *yamux;
    } ctx;
} generic_muxer_ctx_t;

/* ===== Generic Muxer Functions ===== */

static int send_length_prefixed_message_generic(generic_muxer_ctx_t *gmx, uint64_t stream_id, const char *message, int initiator)
{
    if (!gmx || !message)
        return -1;

    switch (gmx->type)
    {
        case MUXER_TYPE_MPLEX:
            return send_length_prefixed_message(gmx->ctx.mplex, stream_id, message, initiator);
        case MUXER_TYPE_YAMUX:
            return send_length_prefixed_message_yamux(gmx->ctx.yamux, (uint32_t)stream_id, message);
        default:
            return -1;
    }
}

static int recv_length_prefixed_message_generic(generic_muxer_ctx_t *gmx, uint64_t stream_id, int initiator, char *buffer, size_t max_len)
{
    if (!gmx || !buffer)
        return -1;

    switch (gmx->type)
    {
        case MUXER_TYPE_MPLEX:
            return recv_length_prefixed_message(gmx->ctx.mplex, stream_id, initiator, buffer, max_len);
        case MUXER_TYPE_YAMUX:
            return recv_length_prefixed_message_yamux(gmx->ctx.yamux, (uint32_t)stream_id, buffer, max_len);
        default:
            return -1;
    }
}

static int process_one_generic(generic_muxer_ctx_t *gmx)
{
    if (!gmx)
    {
        fprintf(stderr, "[PROCESS_ONE_GENERIC] Error: gmx is NULL\n");
        return -1;
    }

    fprintf(stderr, "[PROCESS_ONE_GENERIC] Processing frame, muxer_type=%d\n", gmx->type);

    switch (gmx->type)
    {
        case MUXER_TYPE_MPLEX:
            fprintf(stderr, "[PROCESS_ONE_GENERIC] Calling mplex_process_one\n");
            return libp2p_mplex_process_one(gmx->ctx.mplex) == LIBP2P_MPLEX_OK ? 0 : -1;
        case MUXER_TYPE_YAMUX:
            fprintf(stderr, "[PROCESS_ONE_GENERIC] Calling yamux_process_one_nonblocking\n");
            libp2p_yamux_err_t result = libp2p_yamux_process_one_nonblocking(gmx->ctx.yamux);
            fprintf(stderr, "[PROCESS_ONE_GENERIC] yamux_process_one_nonblocking returned: %d\n", result);

            if (result == LIBP2P_YAMUX_ERR_EOF)
            {
                // Connection closed by remote peer - signal to stop the protocol handler
                fprintf(stderr, "[PROCESS_ONE_GENERIC] Connection closed, stopping protocol handler\n");
                return -2; // Special return code to indicate EOF/stop
            }

            return result == LIBP2P_YAMUX_OK ? 0 : -1;
        default:
            fprintf(stderr, "[PROCESS_ONE_GENERIC] Unknown muxer type: %d\n", gmx->type);
            return -1;
    }
}

// Non-blocking yamux frame processing function
static libp2p_yamux_err_t libp2p_yamux_process_one_nonblocking(libp2p_yamux_ctx_t *ctx)
{
    if (!ctx || !ctx->conn)
    {
        return LIBP2P_YAMUX_ERR_INTERNAL;
    }

    // Try to read the 12-byte yamux header
    uint8_t header[12];
    ssize_t n = libp2p_conn_read(ctx->conn, header, 12);

    if (n == 12)
    {
        // Success - we got the full header
        fprintf(stderr, "[YAMUX_NONBLOCKING] Read complete header\n");
    }
    else if (n == LIBP2P_CONN_ERR_AGAIN)
    {
        // No data available right now
        fprintf(stderr, "[YAMUX_NONBLOCKING] No header data available (read 0/12 bytes)\n");
        return LIBP2P_YAMUX_ERR_AGAIN;
    }
    else if (n == LIBP2P_CONN_ERR_EOF)
    {
        // Connection closed by remote peer - this is normal after test completion
        fprintf(stderr, "[YAMUX_NONBLOCKING] Connection closed by remote peer (EOF)\n");
        return LIBP2P_YAMUX_ERR_EOF;
    }
    else
    {
        // Other read errors
        fprintf(stderr, "[YAMUX_NONBLOCKING] Header read error: %zd\n", n);
        return (libp2p_yamux_err_t)n;
    }

    // Parse the header
    libp2p_yamux_frame_t fr;
    fr.version = header[0];
    fr.type = header[1];
    fr.flags = ntohs(*(uint16_t *)&header[2]);
    fr.stream_id = ntohl(*(uint32_t *)&header[4]);
    fr.length = ntohl(*(uint32_t *)&header[8]);

    // Set data_len based on frame type
    if (fr.type == LIBP2P_YAMUX_DATA)
    {
        fr.data_len = fr.length;
    }
    else
    {
        fr.data_len = 0;
    }

    fprintf(stderr, "[YAMUX] read frame type=%d id=%u flags=0x%x len=%u\n", fr.type, fr.stream_id, fr.flags, fr.length);

    // Read frame data if present
    if (fr.data_len > 0)
    {
        fr.data = malloc(fr.data_len);
        if (!fr.data)
        {
            fprintf(stderr, "[YAMUX_NONBLOCKING] Failed to allocate %zu bytes for frame data\n", (size_t)fr.data_len);
            return LIBP2P_YAMUX_ERR_INTERNAL;
        }

        size_t data_read = 0;
        while (data_read < fr.data_len)
        {
            ssize_t n = libp2p_conn_read(ctx->conn, fr.data + data_read, fr.data_len - data_read);
            if (n > 0)
            {
                data_read += n;
            }
            else if (n == LIBP2P_CONN_ERR_AGAIN)
            {
                fprintf(stderr, "[YAMUX_NONBLOCKING] No data payload available (read %zu/%zu bytes)\n", data_read, (size_t)fr.data_len);
                free(fr.data);
                return LIBP2P_YAMUX_ERR_AGAIN;
            }
            else if (n == LIBP2P_CONN_ERR_EOF)
            {
                fprintf(stderr, "[YAMUX_NONBLOCKING] Connection closed while reading frame data\n");
                free(fr.data);
                return LIBP2P_YAMUX_ERR_EOF;
            }
            else
            {
                fprintf(stderr, "[YAMUX_NONBLOCKING] Data read error: %zd\n", n);
                free(fr.data);
                return (libp2p_yamux_err_t)n;
            }
        }
    }
    else
    {
        fr.data = NULL;
    }

    // Dispatch the frame
    libp2p_yamux_err_t result = libp2p_yamux_dispatch_frame(ctx, &fr);

    if (fr.data)
    {
        free(fr.data);
    }

    return result;
}

/* ===== Internal Helper Functions ===== */

/**
 * @brief Perform multiselect negotiation for a protocol.
 *
 * @param ctx Muxer context
 * @param stream_id Stream identifier
 * @param protocol_id Target protocol ID
 * @param is_initiator True if we're the initiator of the stream
 * @return 0 on success, negative on error
 */
static int negotiate_protocol(generic_muxer_ctx_t *gmx, uint64_t stream_id, const char *protocol_id, int is_initiator)
{
    char buffer[512];

    if (is_initiator)
    {
        // Send multistream header
        if (send_length_prefixed_message_generic(gmx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 1) != 0)
        {
            return -1;
        }

        // Wait for acknowledgment
        int recv_result = recv_length_prefixed_message_generic(gmx, stream_id, is_initiator, buffer, sizeof(buffer));

        if (recv_result < 0)
        {
            return -1;
        }

        if (strcmp(buffer, LIBP2P_MULTISELECT_PROTO_ID "\n") != 0)
        {
            return -1;
        }

        // Send protocol request
        char protocol_request[LIBP2P_PROTOCOL_ID_MAX_LEN + 2];
        snprintf(protocol_request, sizeof(protocol_request), "%s\n", protocol_id);
        if (send_length_prefixed_message_generic(gmx, stream_id, protocol_request, 1) != 0)
        {
            return -1;
        }

        // Wait for protocol acknowledgment
        if (recv_length_prefixed_message_generic(gmx, stream_id, is_initiator, buffer, sizeof(buffer)) < 0)
        {
            return -1;
        }

        char expected[LIBP2P_PROTOCOL_ID_MAX_LEN + 2];
        snprintf(expected, sizeof(expected), "%s\n", protocol_id);
        if (strcmp(buffer, expected) != 0)
        {
            return -1;
        }
    }
    else
    {
        if (recv_length_prefixed_message_generic(gmx, stream_id, 0, buffer, sizeof(buffer)) < 0)
        {
            return -1;
        }

        if (strcmp(buffer, LIBP2P_MULTISELECT_PROTO_ID "\n") != 0)
        {
            return -1;
        }

        // Send acknowledgment
        if (send_length_prefixed_message_generic(gmx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 0) != 0)
        {
            return -1;
        }

        // Receive protocol request
        if (recv_length_prefixed_message_generic(gmx, stream_id, 0, buffer, sizeof(buffer)) < 0)
        {
            return -1;
        }

        // Verify it matches expected protocol
        char expected[LIBP2P_PROTOCOL_ID_MAX_LEN + 2];
        snprintf(expected, sizeof(expected), "%s\n", protocol_id);
        if (strcmp(buffer, expected) != 0)
        {
            return -1;
        }

        // Send protocol acknowledgment
        if (send_length_prefixed_message_generic(gmx, stream_id, expected, 0) != 0)
        {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Find a protocol handler in the registry.
 *
 * @param registry Protocol handler registry
 * @param protocol_id Protocol ID to find
 * @return Handler entry or NULL if not found
 */
static libp2p_protocol_handler_entry_t *find_protocol_handler(libp2p_protocol_handler_registry_t *registry, const char *protocol_id)
{
    pthread_mutex_lock(&registry->mutex);

    libp2p_protocol_handler_entry_t *entry = registry->handlers;
    while (entry)
    {
        if (strcmp(entry->protocol_id, protocol_id) == 0)
        {
            pthread_mutex_unlock(&registry->mutex);
            return entry;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&registry->mutex);
    return NULL;
}

/**
 * @brief Handle an incoming stream with protocol negotiation.
 *
 * @param ctx Protocol handler context
 * @param stream_id Stream identifier
 * @return 0 on success, negative on error
 */
static int handle_incoming_stream(libp2p_protocol_handler_ctx_t *ctx, uint64_t stream_id)
{
    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)ctx->muxer_ctx;
    char buffer[512];

    fprintf(stderr, "[HANDLE_STREAM] Processing stream id=%llu\n", (unsigned long long)stream_id);

    // Receive multistream header
    if (recv_length_prefixed_message_generic(gmx, stream_id, 0, buffer, sizeof(buffer)) < 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to receive multistream header\n");
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Received header: %s", buffer);

    if (strcmp(buffer, LIBP2P_MULTISELECT_PROTO_ID "\n") != 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Invalid multistream header\n");
        return -1;
    }

    // Send acknowledgment
    if (send_length_prefixed_message_generic(gmx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 0) != 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to send multistream ack\n");
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Sent multistream ack\n");

    // Receive protocol request
    if (recv_length_prefixed_message_generic(gmx, stream_id, 0, buffer, sizeof(buffer)) < 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to receive protocol request\n");
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Received protocol request: %s", buffer);

    // Remove trailing newline for lookup
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n')
    {
        buffer[len - 1] = '\0';
    }

    // Find handler for this protocol
    libp2p_protocol_handler_entry_t *entry = find_protocol_handler(ctx->registry, buffer);
    if (!entry)
    {
        fprintf(stderr, "[HANDLE_STREAM] No handler found for protocol: %s\n", buffer);
        // Send "na" (not available) response
        send_length_prefixed_message_generic(gmx, stream_id, LIBP2P_MULTISELECT_NA "\n", 0);
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Found handler for protocol: %s\n", buffer);

    // Send protocol acknowledgment
    char ack[LIBP2P_PROTOCOL_ID_MAX_LEN + 2];
    snprintf(ack, sizeof(ack), "%s\n", buffer);
    if (send_length_prefixed_message_generic(gmx, stream_id, ack, 0) != 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to send protocol ack\n");
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Sent protocol ack\n");

    // No special frame processing needed - let the stream handler handle the data asynchronously

    fprintf(stderr, "[HANDLE_STREAM] Calling protocol handler for %s\n", buffer);

    // Create stream object
    libp2p_stream_t *stream = calloc(1, sizeof(libp2p_stream_t));
    if (!stream)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to allocate stream object\n");
        return -1;
    }

    stream->uconn = ctx->uconn;
    stream->stream_id = stream_id;
    stream->initiator = 0; // Incoming stream
    stream->protocol_id = strdup(buffer);
    stream->ctx = ctx->muxer_ctx;

    // Call the protocol handler
    int result = entry->handler(stream, entry->user_data);
    fprintf(stderr, "[HANDLE_STREAM] Protocol handler returned: %d\n", result);

    // Cleanup
    libp2p_stream_free(stream);

    return result;
}

/* ===== Stream Lifecycle Management ===== */

/**
 * @brief Stream state tracking for connection lifecycle management
 */
typedef struct active_stream_entry
{
    uint64_t stream_id;
    int keep_alive; // 0 = ignore for keep-alive (like ping), 1 = keep connection alive
    struct active_stream_entry *next;
} active_stream_entry_t;

typedef struct
{
    active_stream_entry_t *streams;
    int total_streams;
    int keep_alive_streams;
    pthread_mutex_t mutex;
} stream_tracker_t;

static stream_tracker_t *stream_tracker_new(void)
{
    stream_tracker_t *tracker = calloc(1, sizeof(stream_tracker_t));
    if (!tracker)
        return NULL;

    if (pthread_mutex_init(&tracker->mutex, NULL) != 0)
    {
        free(tracker);
        return NULL;
    }

    return tracker;
}

static void stream_tracker_free(stream_tracker_t *tracker)
{
    if (!tracker)
        return;

    pthread_mutex_lock(&tracker->mutex);
    active_stream_entry_t *entry = tracker->streams;
    while (entry)
    {
        active_stream_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }
    pthread_mutex_unlock(&tracker->mutex);
    pthread_mutex_destroy(&tracker->mutex);
    free(tracker);
}

static void stream_tracker_add_stream(stream_tracker_t *tracker, uint64_t stream_id, int keep_alive)
{
    if (!tracker)
        return;

    active_stream_entry_t *entry = calloc(1, sizeof(active_stream_entry_t));
    if (!entry)
        return;

    entry->stream_id = stream_id;
    entry->keep_alive = keep_alive;

    pthread_mutex_lock(&tracker->mutex);
    entry->next = tracker->streams;
    tracker->streams = entry;
    tracker->total_streams++;
    if (keep_alive)
    {
        tracker->keep_alive_streams++;
    }
    pthread_mutex_unlock(&tracker->mutex);

    fprintf(stderr, "[STREAM_TRACKER] Added stream %llu (keep_alive=%d), total=%d, keep_alive=%d\n", (unsigned long long)stream_id, keep_alive,
            tracker->total_streams, tracker->keep_alive_streams);
}

static void stream_tracker_remove_stream(stream_tracker_t *tracker, uint64_t stream_id)
{
    if (!tracker)
        return;

    pthread_mutex_lock(&tracker->mutex);
    active_stream_entry_t *entry = tracker->streams;
    active_stream_entry_t *prev = NULL;

    while (entry)
    {
        if (entry->stream_id == stream_id)
        {
            if (prev)
            {
                prev->next = entry->next;
            }
            else
            {
                tracker->streams = entry->next;
            }

            tracker->total_streams--;
            if (entry->keep_alive)
            {
                tracker->keep_alive_streams--;
            }

            fprintf(stderr, "[STREAM_TRACKER] Removed stream %llu (keep_alive=%d), remaining=%d, keep_alive=%d\n", (unsigned long long)stream_id,
                    entry->keep_alive, tracker->total_streams, tracker->keep_alive_streams);

            free(entry);
            break;
        }
        prev = entry;
        entry = entry->next;
    }
    pthread_mutex_unlock(&tracker->mutex);
}

static int stream_tracker_should_close_connection(stream_tracker_t *tracker)
{
    if (!tracker)
        return 1;

    pthread_mutex_lock(&tracker->mutex);
    int should_close = (tracker->keep_alive_streams == 0 && tracker->total_streams > 0);
    pthread_mutex_unlock(&tracker->mutex);

    return should_close;
}

/* ===== Protocol Handler State Machine ===== */

typedef enum
{
    HANDLER_STATE_ACTIVE,   // Processing streams and frames
    HANDLER_STATE_DRAINING, // No keep-alive streams, draining remaining streams
    HANDLER_STATE_SHUTDOWN  // Ready to shutdown
} handler_state_t;

typedef struct
{
    handler_state_t state;
    stream_tracker_t *streams;
    int frames_processed_in_cycle;
    int max_frames_per_cycle;
    int total_streams_processed; // Track total streams processed to avoid premature shutdown
    struct timespec last_activity;
    int shutdown_timeout_ms;
} handler_context_t;

static handler_context_t *handler_context_new(void)
{
    handler_context_t *hctx = calloc(1, sizeof(handler_context_t));
    if (!hctx)
        return NULL;

    hctx->state = HANDLER_STATE_ACTIVE;
    hctx->streams = stream_tracker_new();
    hctx->max_frames_per_cycle = 100; // Prevent infinite frame processing
    hctx->shutdown_timeout_ms = 500;  // 500ms timeout for draining
    clock_gettime(CLOCK_MONOTONIC, &hctx->last_activity);

    if (!hctx->streams)
    {
        free(hctx);
        return NULL;
    }

    return hctx;
}

static void handler_context_free(handler_context_t *hctx)
{
    if (!hctx)
        return;
    stream_tracker_free(hctx->streams);
    free(hctx);
}

static void handler_context_update_activity(handler_context_t *hctx) { clock_gettime(CLOCK_MONOTONIC, &hctx->last_activity); }

static int handler_context_is_drain_timeout(handler_context_t *hctx)
{
    if (hctx->state != HANDLER_STATE_DRAINING)
        return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long long elapsed_ms = ((now.tv_sec - hctx->last_activity.tv_sec) * 1000) + ((now.tv_nsec - hctx->last_activity.tv_nsec) / 1000000);

    return elapsed_ms > hctx->shutdown_timeout_ms;
}

/**
 * @brief Enhanced stream handler that tracks stream lifecycle for keep-alive
 */
static int handle_incoming_stream_with_tracking(libp2p_protocol_handler_ctx_t *ctx, uint64_t stream_id)
{
    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)ctx->muxer_ctx;
    handler_context_t *hctx = (handler_context_t *)ctx->handler_context;
    char buffer[512];

    fprintf(stderr, "[HANDLE_STREAM] Processing stream id=%llu\n", (unsigned long long)stream_id);

    // Initially add as keep-alive stream (will be updated for ping)
    stream_tracker_add_stream(hctx->streams, stream_id, 1);

    // Receive multistream header
    if (recv_length_prefixed_message_generic(gmx, stream_id, 0, buffer, sizeof(buffer)) < 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to receive multistream header\n");
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Received header: %s", buffer);

    if (strcmp(buffer, LIBP2P_MULTISELECT_PROTO_ID "\n") != 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Invalid multistream header\n");
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    // Send acknowledgment
    if (send_length_prefixed_message_generic(gmx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 0) != 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to send multistream ack\n");
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Sent multistream ack\n");

    // Receive protocol request
    if (recv_length_prefixed_message_generic(gmx, stream_id, 0, buffer, sizeof(buffer)) < 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to receive protocol request\n");
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Received protocol request: %s", buffer);

    // Remove trailing newline for lookup
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n')
    {
        buffer[len - 1] = '\0';
    }

    // Update keep-alive status for ping protocol (like Rust libp2p)
    int keep_alive = 1;
    if (strcmp(buffer, LIBP2P_PING_PROTO_ID) == 0)
    {
        keep_alive = 0; // Ping streams don't keep connection alive
        stream_tracker_remove_stream(hctx->streams, stream_id);
        stream_tracker_add_stream(hctx->streams, stream_id, keep_alive);
        fprintf(stderr, "[HANDLE_STREAM] Ping protocol detected - marked as non-keep-alive\n");
    }

    // Find handler for this protocol
    libp2p_protocol_handler_entry_t *entry = find_protocol_handler(ctx->registry, buffer);
    if (!entry)
    {
        fprintf(stderr, "[HANDLE_STREAM] No handler found for protocol: %s\n", buffer);
        send_length_prefixed_message_generic(gmx, stream_id, LIBP2P_MULTISELECT_NA "\n", 0);
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Found handler for protocol: %s\n", buffer);

    // Send protocol acknowledgment
    char ack[LIBP2P_PROTOCOL_ID_MAX_LEN + 2];
    snprintf(ack, sizeof(ack), "%s\n", buffer);
    if (send_length_prefixed_message_generic(gmx, stream_id, ack, 0) != 0)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to send protocol ack\n");
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    fprintf(stderr, "[HANDLE_STREAM] Sent protocol ack\n");
    fprintf(stderr, "[HANDLE_STREAM] Calling protocol handler for %s\n", buffer);

    // Create stream object
    libp2p_stream_t *stream = calloc(1, sizeof(libp2p_stream_t));
    if (!stream)
    {
        fprintf(stderr, "[HANDLE_STREAM] Failed to allocate stream object\n");
        stream_tracker_remove_stream(hctx->streams, stream_id);
        return -1;
    }

    stream->uconn = ctx->uconn;
    stream->stream_id = stream_id;
    stream->initiator = 0; // Incoming stream
    stream->protocol_id = strdup(buffer);
    stream->ctx = ctx->muxer_ctx;

    // Call the protocol handler
    int result = entry->handler(stream, entry->user_data);
    fprintf(stderr, "[HANDLE_STREAM] Protocol handler returned: %d\n", result);

    // Stream completed - remove from tracker
    stream_tracker_remove_stream(hctx->streams, stream_id);

    // Cleanup
    libp2p_stream_free(stream);

    return result;
}

/**
 * @brief Event-driven protocol handler thread - inspired by Rust libp2p architecture
 *
 * This replaces the old polling-based approach with a proper event-driven model:
 * - Processes frames until none available
 * - Handles streams as they arrive
 * - Uses stream lifecycle tracking for connection keep-alive
 * - No arbitrary idle cycles or timeouts
 * - Natural termination based on protocol completion
 */
static void *protocol_handler_thread(void *arg)
{
    libp2p_protocol_handler_ctx_t *ctx = (libp2p_protocol_handler_ctx_t *)arg;
    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)ctx->muxer_ctx;

    // Initialize handler context with stream tracking
    handler_context_t *hctx = handler_context_new();
    if (!hctx)
    {
        fprintf(stderr, "[PROTOCOL_HANDLER] Failed to create handler context\n");
        return NULL;
    }
    ctx->handler_context = hctx;

    fprintf(stderr, "[PROTOCOL_HANDLER] Event-driven thread started, muxer_type=%s\n",
            gmx->type == MUXER_TYPE_YAMUX   ? "yamux"
            : gmx->type == MUXER_TYPE_MPLEX ? "mplex"
                                            : "unknown");

    while (!ctx->stop_flag)
    {
        int work_done = 0;

        // ==== PHASE 1: Process all available frames ====
        hctx->frames_processed_in_cycle = 0;

        while (hctx->frames_processed_in_cycle < hctx->max_frames_per_cycle && !ctx->stop_flag)
        {
            int frame_result = process_one_generic(gmx);

            if (frame_result == 0)
            {
                // Frame processed successfully
                hctx->frames_processed_in_cycle++;
                work_done = 1;
                handler_context_update_activity(hctx);
            }
            else if (frame_result == -2)
            {
                // EOF/connection closed by remote
                fprintf(stderr, "[PROTOCOL_HANDLER] Connection closed by remote, initiating graceful shutdown\n");
                hctx->state = HANDLER_STATE_SHUTDOWN;
                ctx->stop_flag = 1;
                break;
            }
            else
            {
                // No more frames available right now
                break;
            }
        }

        if (hctx->frames_processed_in_cycle > 0)
        {
            fprintf(stderr, "[PROTOCOL_HANDLER] Processed %d frames in cycle\n", hctx->frames_processed_in_cycle);
        }

        // ==== PHASE 2: Handle new incoming streams ====
        int streams_processed = 0;

        if (gmx->type == MUXER_TYPE_MPLEX)
        {
            libp2p_mplex_stream_t *new_stream = NULL;
            while (1)
            {
                libp2p_mplex_err_t accept_result = libp2p_mplex_accept_stream(gmx->ctx.mplex, &new_stream);

                if (accept_result == LIBP2P_MPLEX_OK && new_stream)
                {
                    fprintf(stderr, "[PROTOCOL_HANDLER] Accepted MPLEX stream id=%" PRIu64 "\n", new_stream->id);
                    int result = handle_incoming_stream_with_tracking(ctx, new_stream->id);
                    streams_processed++;
                    hctx->total_streams_processed++;
                    work_done = 1;
                    handler_context_update_activity(hctx);
                    new_stream = NULL;
                }
                else if (accept_result == LIBP2P_MPLEX_ERR_AGAIN)
                {
                    // No more streams available
                    break;
                }
                else
                {
                    // Error accepting stream
                    break;
                }
            }
        }
        else if (gmx->type == MUXER_TYPE_YAMUX)
        {
            libp2p_yamux_stream_t *new_stream = NULL;
            while (1)
            {
                libp2p_yamux_err_t accept_result = libp2p_yamux_accept_stream(gmx->ctx.yamux, &new_stream);

                if (accept_result == LIBP2P_YAMUX_OK && new_stream)
                {
                    fprintf(stderr, "[PROTOCOL_HANDLER] Accepted YAMUX stream id=%u\n", new_stream->id);
                    int result = handle_incoming_stream_with_tracking(ctx, new_stream->id);
                    streams_processed++;
                    hctx->total_streams_processed++;
                    work_done = 1;
                    handler_context_update_activity(hctx);
                    new_stream = NULL;
                }
                else if (accept_result == LIBP2P_YAMUX_ERR_AGAIN)
                {
                    // No more streams available
                    break;
                }
                else
                {
                    // Error accepting stream
                    break;
                }
            }
        }

        if (streams_processed > 0)
        {
            fprintf(stderr, "[PROTOCOL_HANDLER] Processed %d new streams\n", streams_processed);
        }

        // ==== PHASE 3: Connection lifecycle management ====

        // Check current stream state
        pthread_mutex_lock(&hctx->streams->mutex);
        int total_streams = hctx->streams->total_streams;
        int keep_alive_streams = hctx->streams->keep_alive_streams;
        pthread_mutex_unlock(&hctx->streams->mutex);

        // Update state based on stream tracker
        if (hctx->state == HANDLER_STATE_ACTIVE)
        {
            // Only consider shutdown after processing at least one stream
            if (hctx->total_streams_processed > 0)
            {
                if (total_streams == 0)
                {
                    fprintf(stderr, "[PROTOCOL_HANDLER] All streams completed after processing %d streams, ready for immediate shutdown\n",
                            hctx->total_streams_processed);
                    hctx->state = HANDLER_STATE_SHUTDOWN;
                    ctx->stop_flag = 1;
                }
                else if (keep_alive_streams == 0 && total_streams > 0)
                {
                    fprintf(stderr, "[PROTOCOL_HANDLER] No keep-alive streams remaining (%d non-keep-alive streams), entering drain state\n",
                            total_streams);
                    hctx->state = HANDLER_STATE_DRAINING;
                    handler_context_update_activity(hctx);
                }
            }
        }

        // Check if we should shutdown from draining state
        if (hctx->state == HANDLER_STATE_DRAINING)
        {
            if (total_streams == 0)
            {
                fprintf(stderr, "[PROTOCOL_HANDLER] All streams completed, ready for shutdown\n");
                hctx->state = HANDLER_STATE_SHUTDOWN;
                ctx->stop_flag = 1;
            }
            else if (handler_context_is_drain_timeout(hctx))
            {
                fprintf(stderr, "[PROTOCOL_HANDLER] Drain timeout reached, forcing shutdown\n");
                hctx->state = HANDLER_STATE_SHUTDOWN;
                ctx->stop_flag = 1;
            }
        }

        // ==== PHASE 4: Event loop timing ====

        if (!work_done && !ctx->stop_flag)
        {
            // No work was done this cycle - brief sleep to prevent busy waiting
            // This is much shorter than the old 10ms idle sleep
            usleep(1000); // 1ms - responsive but not busy-waiting
        }
        // If work was done, continue immediately to next cycle
    }

    fprintf(stderr, "[PROTOCOL_HANDLER] Event-driven thread shutting down gracefully\n");
    handler_context_free(hctx);
    ctx->handler_context = NULL;
    return NULL;
}

/* ===== Registry Management Implementation ===== */
libp2p_protocol_handler_registry_t *libp2p_protocol_handler_registry_new(void)
{
    libp2p_protocol_handler_registry_t *registry = calloc(1, sizeof(libp2p_protocol_handler_registry_t));
    if (!registry)
    {
        return NULL;
    }

    if (pthread_mutex_init(&registry->mutex, NULL) != 0)
    {
        free(registry);
        return NULL;
    }

    return registry;
}

void libp2p_protocol_handler_registry_free(libp2p_protocol_handler_registry_t *registry)
{
    if (!registry)
    {
        return;
    }

    pthread_mutex_lock(&registry->mutex);

    libp2p_protocol_handler_entry_t *entry = registry->handlers;
    while (entry)
    {
        libp2p_protocol_handler_entry_t *next = entry->next;
        free(entry);
        entry = next;
    }

    pthread_mutex_unlock(&registry->mutex);
    pthread_mutex_destroy(&registry->mutex);
    free(registry);
}

int libp2p_register_protocol_handler(libp2p_protocol_handler_registry_t *registry, const char *protocol_id, libp2p_protocol_handler_t handler,
                                     void *user_data)
{
    if (!registry || !protocol_id || !handler)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    if (strlen(protocol_id) >= LIBP2P_PROTOCOL_ID_MAX_LEN)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    pthread_mutex_lock(&registry->mutex);

    // Check if protocol already exists
    libp2p_protocol_handler_entry_t *existing = registry->handlers;
    while (existing)
    {
        if (strcmp(existing->protocol_id, protocol_id) == 0)
        {
            pthread_mutex_unlock(&registry->mutex);
            return LIBP2P_PROTOCOL_HANDLER_ERR_PROTOCOL_EXISTS;
        }
        existing = existing->next;
    }

    // Create new entry
    libp2p_protocol_handler_entry_t *entry = calloc(1, sizeof(libp2p_protocol_handler_entry_t));
    if (!entry)
    {
        pthread_mutex_unlock(&registry->mutex);
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    strncpy(entry->protocol_id, protocol_id, LIBP2P_PROTOCOL_ID_MAX_LEN - 1);
    entry->handler = handler;
    entry->user_data = user_data;
    entry->next = registry->handlers;
    registry->handlers = entry;

    pthread_mutex_unlock(&registry->mutex);
    return LIBP2P_PROTOCOL_HANDLER_OK;
}

int libp2p_unregister_protocol_handler(libp2p_protocol_handler_registry_t *registry, const char *protocol_id)
{
    if (!registry || !protocol_id)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    pthread_mutex_lock(&registry->mutex);

    libp2p_protocol_handler_entry_t *entry = registry->handlers;
    libp2p_protocol_handler_entry_t *prev = NULL;

    while (entry)
    {
        if (strcmp(entry->protocol_id, protocol_id) == 0)
        {
            if (prev)
            {
                prev->next = entry->next;
            }
            else
            {
                registry->handlers = entry->next;
            }
            free(entry);
            pthread_mutex_unlock(&registry->mutex);
            return LIBP2P_PROTOCOL_HANDLER_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_mutex_unlock(&registry->mutex);
    return LIBP2P_PROTOCOL_HANDLER_ERR_PROTOCOL_NOT_FOUND;
}

/* ===== Stream Management Implementation ===== */

libp2p_protocol_handler_ctx_t *libp2p_protocol_handler_ctx_new(libp2p_protocol_handler_registry_t *registry, libp2p_uconn_t *uconn)
{
    if (!registry || !uconn)
    {
        return NULL;
    }

    libp2p_protocol_handler_ctx_t *ctx = calloc(1, sizeof(libp2p_protocol_handler_ctx_t));
    if (!ctx)
    {
        return NULL;
    }

    ctx->registry = registry;
    ctx->uconn = uconn;

    // Create generic muxer context
    generic_muxer_ctx_t *gmx = calloc(1, sizeof(generic_muxer_ctx_t));
    if (!gmx)
    {
        free(ctx);
        return NULL;
    }

    // Detect which muxer was negotiated and create appropriate context
    muxer_type_t muxer_type = detect_muxer_type(uconn->muxer);
    gmx->type = muxer_type;

    switch (muxer_type)
    {
        case MUXER_TYPE_MPLEX:
            // Use the mplex context from the muxer (similar to yamux)
            gmx->ctx.mplex = (libp2p_mplex_ctx_t *)uconn->muxer->ctx;
            if (!gmx->ctx.mplex)
            {
                free(gmx);
                free(ctx);
                return NULL;
            }
            break;
        case MUXER_TYPE_YAMUX:
            // Use the yamux context that was created during negotiation
            gmx->ctx.yamux = (libp2p_yamux_ctx_t *)uconn->muxer->ctx;
            if (!gmx->ctx.yamux)
            {
                free(gmx);
                free(ctx);
                return NULL;
            }
            break;
        default:
            fprintf(stderr, "Unknown muxer type detected\n");
            free(gmx);
            free(ctx);
            return NULL;
    }

    ctx->muxer_ctx = gmx;

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0)
    {
        if (muxer_type == MUXER_TYPE_MPLEX)
        {
            libp2p_mplex_ctx_free(gmx->ctx.mplex);
        }
        // Note: For yamux, we don't free the context as it's owned by the muxer
        free(gmx);
        free(ctx);
        return NULL;
    }

    return ctx;
}

int libp2p_protocol_handler_start(libp2p_protocol_handler_ctx_t *ctx)
{
    if (!ctx)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    ctx->stop_flag = 0;

    if (pthread_create(&ctx->handler_thread, NULL, protocol_handler_thread, ctx) != 0)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    return LIBP2P_PROTOCOL_HANDLER_OK;
}

void libp2p_protocol_handler_stop(libp2p_protocol_handler_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    ctx->stop_flag = 1;
    pthread_join(ctx->handler_thread, NULL);
}

void libp2p_protocol_handler_ctx_free(libp2p_protocol_handler_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    if (!ctx->stop_flag)
    {
        libp2p_protocol_handler_stop(ctx);
    }

    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)ctx->muxer_ctx;
    if (gmx)
    {
        // Note: For both mplex and yamux, we don't free the context as it's owned by the muxer
        free(gmx);
    }
    pthread_mutex_destroy(&ctx->mutex);
    free(ctx);
}

/* ===== Stream Operations Implementation ===== */

int libp2p_protocol_open_stream(libp2p_uconn_t *uconn, const char *protocol_id, libp2p_stream_t **stream)
{
    if (!uconn || !protocol_id || !stream)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    // Create generic muxer context
    generic_muxer_ctx_t *gmx = calloc(1, sizeof(generic_muxer_ctx_t));
    if (!gmx)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    // Detect muxer type and create appropriate context
    muxer_type_t muxer_type = detect_muxer_type(uconn->muxer);
    gmx->type = muxer_type;

    uint64_t stream_id;

    switch (muxer_type)
    {
        case MUXER_TYPE_MPLEX:
            // Use the mplex context from the muxer (similar to yamux)
            gmx->ctx.mplex = (libp2p_mplex_ctx_t *)uconn->muxer->ctx;
            if (!gmx->ctx.mplex)
            {
                free(gmx);
                return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
            }

            // Open a new mplex stream
            if (libp2p_mplex_stream_open(gmx->ctx.mplex, NULL, 0, &stream_id) != LIBP2P_MPLEX_OK)
            {
                free(gmx);
                return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
            }
            break;

        case MUXER_TYPE_YAMUX:
            // Use the yamux context from the muxer
            gmx->ctx.yamux = (libp2p_yamux_ctx_t *)uconn->muxer->ctx;
            if (!gmx->ctx.yamux)
            {
                free(gmx);
                return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
            }

            // Open a new yamux stream
            uint32_t yamux_stream_id;
            if (libp2p_yamux_stream_open(gmx->ctx.yamux, &yamux_stream_id) != LIBP2P_YAMUX_OK)
            {
                free(gmx);
                return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
            }
            stream_id = yamux_stream_id;
            break;

        default:
            free(gmx);
            return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    // Perform protocol negotiation
    if (negotiate_protocol(gmx, stream_id, protocol_id, 1) != 0)
    {
        free(gmx);
        return LIBP2P_PROTOCOL_HANDLER_ERR_MULTISELECT;
    }

    // Create stream object
    libp2p_stream_t *new_stream = calloc(1, sizeof(libp2p_stream_t));
    if (!new_stream)
    {
        free(gmx);
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    new_stream->uconn = uconn;
    new_stream->stream_id = stream_id;
    new_stream->initiator = 1;
    new_stream->protocol_id = strdup(protocol_id);
    new_stream->ctx = gmx;

    *stream = new_stream;
    return LIBP2P_PROTOCOL_HANDLER_OK;
}

int libp2p_protocol_open_stream_with_context(libp2p_mplex_ctx_t *mx, libp2p_uconn_t *uconn, const char *protocol_id, libp2p_stream_t **stream)
{
    if (!mx || !uconn || !protocol_id || !stream)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    // Open a new stream using the existing mplex context
    uint64_t stream_id;
    libp2p_mplex_err_t open_result = libp2p_mplex_stream_open(mx, NULL, 0, &stream_id);

    if (open_result != LIBP2P_MPLEX_OK)
    {

        // Add more details about the error
        const char *err_str = "UNKNOWN";
        switch (open_result)
        {
            case LIBP2P_MPLEX_ERR_NULL_PTR:
                err_str = "NULL_PTR";
                break;
            case LIBP2P_MPLEX_ERR_HANDSHAKE:
                err_str = "HANDSHAKE";
                break;
            case LIBP2P_MPLEX_ERR_INTERNAL:
                err_str = "INTERNAL";
                break;
            case LIBP2P_MPLEX_ERR_PROTO_MAL:
                err_str = "PROTO_MAL";
                break;
            case LIBP2P_MPLEX_ERR_TIMEOUT:
                err_str = "TIMEOUT";
                break;
            case LIBP2P_MPLEX_ERR_EOF:
                err_str = "EOF";
                break;
            case LIBP2P_MPLEX_ERR_AGAIN:
                err_str = "AGAIN";
                break;
            case LIBP2P_MPLEX_ERR_RESET:
                err_str = "RESET";
                break;
            default:
                break;
        }
        return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
    }

    // Create generic muxer wrapper for negotiation
    generic_muxer_ctx_t gmx_wrapper = {.type = MUXER_TYPE_MPLEX, .ctx.mplex = mx};

    // Perform protocol negotiation
    if (negotiate_protocol(&gmx_wrapper, stream_id, protocol_id, 1) != 0)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_MULTISELECT;
    }

    // Create stream object
    libp2p_stream_t *new_stream = calloc(1, sizeof(libp2p_stream_t));
    if (!new_stream)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    new_stream->uconn = uconn;
    new_stream->stream_id = stream_id;
    new_stream->initiator = 1;
    new_stream->protocol_id = strdup(protocol_id);
    new_stream->ctx = mx; // Reuse the existing context

    *stream = new_stream;
    return LIBP2P_PROTOCOL_HANDLER_OK;
}

ssize_t libp2p_stream_read(libp2p_stream_t *stream, void *buf, size_t len)
{
    if (!stream || !buf)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)stream->ctx;

    // Process all available frames before attempting to read
    // This ensures stream data is properly buffered before reading
    int processed_frames = 0;
    for (int i = 0; i < 10; i++) // Process up to 10 frames
    {
        if (process_one_generic(gmx) == 0)
        {
            processed_frames++;
        }
        else
        {
            break; // No more frames to process
        }
    }

    // Now attempt to read from the buffered stream data
    size_t bytes_read = 0;
    int recv_result = -1;

    if (gmx->type == MUXER_TYPE_MPLEX)
    {
        libp2p_mplex_err_t mplex_result =
            libp2p_mplex_stream_recv(gmx->ctx.mplex, stream->stream_id, stream->initiator, (uint8_t *)buf, len, &bytes_read);
        if (mplex_result == LIBP2P_MPLEX_OK)
        {
            recv_result = 0;
        }
        else if (mplex_result == LIBP2P_MPLEX_ERR_EOF)
        {
            return 0; // End of stream
        }
        else if (mplex_result == LIBP2P_MPLEX_ERR_AGAIN)
        {
            return -5; // EAGAIN - no data available yet
        }
    }
    else if (gmx->type == MUXER_TYPE_YAMUX)
    {
        libp2p_yamux_err_t yamux_result = libp2p_yamux_stream_recv(gmx->ctx.yamux, (uint32_t)stream->stream_id, (uint8_t *)buf, len, &bytes_read);
        if (yamux_result == LIBP2P_YAMUX_OK)
        {
            recv_result = 0;
        }
        else if (yamux_result == LIBP2P_YAMUX_ERR_EOF)
        {
            return 0; // End of stream
        }
        else if (yamux_result == LIBP2P_YAMUX_ERR_AGAIN)
        {
            return -5; // EAGAIN - no data available yet
        }
    }

    if (recv_result != 0)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
    }

    return (ssize_t)bytes_read;
}

ssize_t libp2p_stream_write(libp2p_stream_t *stream, const void *data, size_t len)
{
    if (!stream || !data)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)stream->ctx;

    if (gmx->type == MUXER_TYPE_MPLEX)
    {
        if (libp2p_mplex_stream_send(gmx->ctx.mplex, stream->stream_id, stream->initiator, (const uint8_t *)data, len) != LIBP2P_MPLEX_OK)
        {
            return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
        }
    }
    else if (gmx->type == MUXER_TYPE_YAMUX)
    {
        if (libp2p_yamux_stream_send(gmx->ctx.yamux, (uint32_t)stream->stream_id, (const uint8_t *)data, len, 0) != LIBP2P_YAMUX_OK)
        {
            return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
        }
    }
    else
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
    }

    return (ssize_t)len;
}

void libp2p_stream_close(libp2p_stream_t *stream)
{
    if (!stream)
    {
        return;
    }

    generic_muxer_ctx_t *gmx = (generic_muxer_ctx_t *)stream->ctx;

    if (gmx->type == MUXER_TYPE_MPLEX)
    {
        libp2p_mplex_stream_close(gmx->ctx.mplex, stream->stream_id, stream->initiator);
    }
    else if (gmx->type == MUXER_TYPE_YAMUX)
    {
        libp2p_yamux_stream_close(gmx->ctx.yamux, (uint32_t)stream->stream_id);
    }
}

void libp2p_stream_free(libp2p_stream_t *stream)
{
    if (!stream)
    {
        return;
    }

    free(stream->protocol_id);
    free(stream);
}

const peer_id_t *libp2p_stream_remote_peer(libp2p_stream_t *stream)
{
    if (!stream || !stream->uconn)
    {
        return NULL;
    }

    return stream->uconn->remote_peer;
}