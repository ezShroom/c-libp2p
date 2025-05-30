#include "protocol/protocol_handler.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/mplex/protocol_mplex.h"
#include "transport/upgrader.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
static int negotiate_protocol(void *mux_ctx, uint64_t stream_id, const char *protocol_id, int is_initiator)
{
    char buffer[512];

    if (is_initiator)
    {
        // Send multistream header
        if (send_length_prefixed_message(mux_ctx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 1) != 0)
        {
            return -1;
        }

        // Wait for acknowledgment
        int recv_result = recv_length_prefixed_message(mux_ctx, stream_id, is_initiator, buffer, sizeof(buffer));

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
        if (send_length_prefixed_message(mux_ctx, stream_id, protocol_request, 1) != 0)
        {
            return -1;
        }

        // Wait for protocol acknowledgment
        if (recv_length_prefixed_message(mux_ctx, stream_id, is_initiator, buffer, sizeof(buffer)) < 0)
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
        if (recv_length_prefixed_message(mux_ctx, stream_id, 0, buffer, sizeof(buffer)) < 0)
        {
            return -1;
        }

        if (strcmp(buffer, LIBP2P_MULTISELECT_PROTO_ID "\n") != 0)
        {
            return -1;
        }

        // Send acknowledgment
        if (send_length_prefixed_message(mux_ctx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 0) != 0)
        {
            return -1;
        }

        // Receive protocol request
        if (recv_length_prefixed_message(mux_ctx, stream_id, 0, buffer, sizeof(buffer)) < 0)
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
        if (send_length_prefixed_message(mux_ctx, stream_id, expected, 0) != 0)
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
    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)ctx->muxer_ctx;
    char buffer[512];

    // Receive multistream header
    if (recv_length_prefixed_message(mx, stream_id, 0, buffer, sizeof(buffer)) < 0)
    {
        return -1;
    }

    if (strcmp(buffer, LIBP2P_MULTISELECT_PROTO_ID "\n") != 0)
    {
        return -1;
    }

    // Send acknowledgment
    if (send_length_prefixed_message(mx, stream_id, LIBP2P_MULTISELECT_PROTO_ID "\n", 0) != 0)
    {
        return -1;
    }

    // Receive protocol request
    if (recv_length_prefixed_message(mx, stream_id, 0, buffer, sizeof(buffer)) < 0)
    {
        return -1;
    }

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
        // Send "na" (not available) response
        send_length_prefixed_message(mx, stream_id, LIBP2P_MULTISELECT_NA "\n", 0);
        return -1;
    }

    // Send protocol acknowledgment
    char ack[LIBP2P_PROTOCOL_ID_MAX_LEN + 2];
    snprintf(ack, sizeof(ack), "%s\n", buffer);
    if (send_length_prefixed_message(mx, stream_id, ack, 0) != 0)
    {
        return -1;
    }

    // Create stream object
    libp2p_stream_t *stream = calloc(1, sizeof(libp2p_stream_t));
    if (!stream)
    {
        return -1;
    }

    stream->uconn = ctx->uconn;
    stream->stream_id = stream_id;
    stream->initiator = 0; // Incoming stream
    stream->protocol_id = strdup(buffer);
    stream->ctx = ctx->muxer_ctx;

    // Call the protocol handler
    int result = entry->handler(stream, entry->user_data);

    // Cleanup
    libp2p_stream_free(stream);

    return result;
}

/**
 * @brief Main thread function for handling incoming streams.
 *
 * @param arg Protocol handler context
 * @return NULL
 */
static void *protocol_handler_thread(void *arg)
{
    libp2p_protocol_handler_ctx_t *ctx = (libp2p_protocol_handler_ctx_t *)arg;
    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)ctx->muxer_ctx;

    int frame_count = 0;
    int stream_count = 0;

    while (!ctx->stop_flag)
    {
        // Process one mplex frame
        libp2p_mplex_err_t err = libp2p_mplex_process_one(mx);
        if (err == LIBP2P_MPLEX_OK)
        {
            frame_count++;
        }
        else if (err != LIBP2P_MPLEX_ERR_AGAIN)
        {
            break;
        }

        // Check for new incoming streams
        libp2p_mplex_stream_t *new_stream = NULL;
        if (libp2p_mplex_accept_stream(mx, &new_stream) == LIBP2P_MPLEX_OK && new_stream)
        {
            stream_count++;
            // Handle the new stream
            int result = handle_incoming_stream(ctx, new_stream->id);
        }

        // Small delay to avoid busy waiting
        usleep(1000); // 1ms
    }

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
    ctx->muxer_ctx = libp2p_mplex_ctx_new(uconn->conn);
    if (!ctx->muxer_ctx)
    {
        free(ctx);
        return NULL;
    }

    if (pthread_mutex_init(&ctx->mutex, NULL) != 0)
    {
        libp2p_mplex_ctx_free((libp2p_mplex_ctx_t *)ctx->muxer_ctx);
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

    libp2p_mplex_ctx_free((libp2p_mplex_ctx_t *)ctx->muxer_ctx);
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

    // Create mplex context for this connection
    libp2p_mplex_ctx_t *mx = libp2p_mplex_ctx_new(uconn->conn);
    if (!mx)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    // Open a new stream
    uint64_t stream_id;
    if (libp2p_mplex_stream_open(mx, NULL, 0, &stream_id) != LIBP2P_MPLEX_OK)
    {
        libp2p_mplex_ctx_free(mx);
        return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
    }

    // Perform protocol negotiation
    if (negotiate_protocol(mx, stream_id, protocol_id, 1) != 0)
    {
        libp2p_mplex_ctx_free(mx);
        return LIBP2P_PROTOCOL_HANDLER_ERR_MULTISELECT;
    }

    // Create stream object
    libp2p_stream_t *new_stream = calloc(1, sizeof(libp2p_stream_t));
    if (!new_stream)
    {
        libp2p_mplex_ctx_free(mx);
        return LIBP2P_PROTOCOL_HANDLER_ERR_INTERNAL;
    }

    new_stream->uconn = uconn;
    new_stream->stream_id = stream_id;
    new_stream->initiator = 1;
    new_stream->protocol_id = strdup(protocol_id);
    new_stream->ctx = mx;

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

    // Perform protocol negotiation
    if (negotiate_protocol(mx, stream_id, protocol_id, 1) != 0)
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

    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)stream->ctx;

    // Retry logic with mplex frame processing (similar to recv_length_prefixed_message)
    const int max_retries = 10; // Reduced from 100 to 10 retries
    for (int retry = 1; retry <= max_retries; retry++)
    {
        size_t bytes_read = 0;
        libp2p_mplex_err_t recv_result = libp2p_mplex_stream_recv(mx, stream->stream_id, stream->initiator, (uint8_t *)buf, len, &bytes_read);

        if (recv_result != LIBP2P_MPLEX_OK)
        {
            if (recv_result == LIBP2P_MPLEX_ERR_EOF)
            {
                return 0; // End of stream
            }
            return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
        }

        if (bytes_read > 0)
        {
            return (ssize_t)bytes_read;
        }

        // No data available, process incoming frames
        libp2p_mplex_err_t process_result = libp2p_mplex_process_one(mx);
        if (process_result == LIBP2P_MPLEX_OK)
        {
            // Successfully processed a frame, try reading again immediately
            continue;
        }
        else if (process_result == LIBP2P_MPLEX_ERR_AGAIN)
        {
            // No data to process, add small delay
            usleep(1000); // 1ms
        }
        else
        {
            // Error in processing
            return LIBP2P_PROTOCOL_HANDLER_ERR_STREAM;
        }
    }

    return 0; // Timeout - no data received
}

ssize_t libp2p_stream_write(libp2p_stream_t *stream, const void *data, size_t len)
{
    if (!stream || !data)
    {
        return LIBP2P_PROTOCOL_HANDLER_ERR_NULL_PTR;
    }

    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)stream->ctx;
    if (libp2p_mplex_stream_send(mx, stream->stream_id, stream->initiator, (const uint8_t *)data, len) != LIBP2P_MPLEX_OK)
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

    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)stream->ctx;
    libp2p_mplex_stream_close(mx, stream->stream_id, stream->initiator);
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