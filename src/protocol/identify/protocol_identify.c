#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/identify/protocol_identify.h"
#include "protocol/mplex/protocol_mplex.h"
#include "protocol/protocol_handler.h"

#define IDENTIFY_PUBLIC_KEY_TAG 0x0A
#define IDENTIFY_LISTEN_ADDRS_TAG 0x12
#define IDENTIFY_PROTOCOLS_TAG 0x1A
#define IDENTIFY_OBSERVED_ADDR_TAG 0x22
#define IDENTIFY_PROTOCOL_VERSION_TAG 0x2A
#define IDENTIFY_AGENT_VERSION_TAG 0x32

static inline int varint_is_minimal(uint64_t v, size_t len)
{
    uint8_t tmp[10];
    size_t min_len;
    if (unsigned_varint_encode(v, tmp, sizeof(tmp), &min_len) != UNSIGNED_VARINT_OK)
        return 0;
    return min_len == len;
}

int libp2p_identify_message_decode(const uint8_t *buf, size_t len, libp2p_identify_t **out_msg)
{
    if (!buf || !out_msg)
        return -1;
    libp2p_identify_t *msg = calloc(1, sizeof(*msg));
    if (!msg)
        return -1;
    size_t off = 0, sz = 0;
    while (off < len)
    {
        uint64_t tag = 0, flen = 0;
        if (unsigned_varint_decode(buf + off, len - off, &tag, &sz) != UNSIGNED_VARINT_OK || !varint_is_minimal(tag, sz))
            goto fail;
        off += sz;
        if (unsigned_varint_decode(buf + off, len - off, &flen, &sz) != UNSIGNED_VARINT_OK || flen > len - off - sz || !varint_is_minimal(flen, sz))
            goto fail;
        off += sz;
        const uint8_t *field = buf + off;
        off += (size_t)flen;
        switch (tag)
        {
            case IDENTIFY_PUBLIC_KEY_TAG:
                msg->public_key = malloc(flen);
                if (!msg->public_key)
                    goto fail;
                memcpy(msg->public_key, field, flen);
                msg->public_key_len = (size_t)flen;
                break;
            case IDENTIFY_LISTEN_ADDRS_TAG:
            {
                uint8_t **addrs = realloc(msg->listen_addrs, (msg->num_listen_addrs + 1) * sizeof(uint8_t *));
                size_t *lens = realloc(msg->listen_addrs_lens, (msg->num_listen_addrs + 1) * sizeof(size_t));
                if (!addrs || !lens)
                {
                    free(addrs);
                    free(lens);
                    goto fail;
                }
                msg->listen_addrs = addrs;
                msg->listen_addrs_lens = lens;
                uint8_t *copy = malloc(flen);
                if (!copy)
                    goto fail;
                memcpy(copy, field, flen);
                msg->listen_addrs[msg->num_listen_addrs] = copy;
                msg->listen_addrs_lens[msg->num_listen_addrs] = (size_t)flen;
                msg->num_listen_addrs++;
                break;
            }
            case IDENTIFY_PROTOCOLS_TAG:
            {
                char **protos = realloc(msg->protocols, (msg->num_protocols + 1) * sizeof(char *));
                if (!protos)
                    goto fail;
                msg->protocols = protos;
                char *copy = malloc(flen + 1);
                if (!copy)
                    goto fail;
                memcpy(copy, field, flen);
                copy[flen] = '\0';
                msg->protocols[msg->num_protocols] = copy;
                msg->num_protocols++;
                break;
            }
            case IDENTIFY_OBSERVED_ADDR_TAG:
                msg->observed_addr = malloc(flen);
                if (!msg->observed_addr)
                    goto fail;
                memcpy(msg->observed_addr, field, flen);
                msg->observed_addr_len = (size_t)flen;
                break;
            case IDENTIFY_PROTOCOL_VERSION_TAG:
                msg->protocol_version = malloc(flen + 1);
                if (!msg->protocol_version)
                    goto fail;
                memcpy(msg->protocol_version, field, flen);
                msg->protocol_version[flen] = '\0';
                break;
            case IDENTIFY_AGENT_VERSION_TAG:
                msg->agent_version = malloc(flen + 1);
                if (!msg->agent_version)
                    goto fail;
                memcpy(msg->agent_version, field, flen);
                msg->agent_version[flen] = '\0';
                break;
            default:
                /* unknown field - ignore */
                break;
        }
    }
    *out_msg = msg;
    return 0;
fail:
    libp2p_identify_free(msg);
    return -1;
}

int libp2p_identify_message_encode(const libp2p_identify_t *msg, uint8_t **out_buf, size_t *out_len)
{
    if (!msg || !out_buf || !out_len)
        return -1;

    *out_buf = NULL;
    *out_len = 0;

    // Calculate total size needed
    size_t total_size = 0;

    // Field 1: public_key
    if (msg->public_key && msg->public_key_len > 0)
    {
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(msg->public_key_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + msg->public_key_len;
    }

    // Field 2: listen_addrs (repeated)
    for (size_t i = 0; i < msg->num_listen_addrs; i++)
    {
        if (msg->listen_addrs[i] && msg->listen_addrs_lens[i] > 0)
        {
            total_size += 1; // tag
            size_t len_varint_size = 0;
            uint8_t tmp[10];
            if (unsigned_varint_encode(msg->listen_addrs_lens[i], tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
                return -1;
            total_size += len_varint_size + msg->listen_addrs_lens[i];
        }
    }

    // Field 3: protocols (repeated)
    for (size_t i = 0; i < msg->num_protocols; i++)
    {
        if (msg->protocols[i])
        {
            size_t proto_len = strlen(msg->protocols[i]);
            total_size += 1; // tag
            size_t len_varint_size = 0;
            uint8_t tmp[10];
            if (unsigned_varint_encode(proto_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
                return -1;
            total_size += len_varint_size + proto_len;
        }
    }

    // Field 4: observed_addr
    if (msg->observed_addr && msg->observed_addr_len > 0)
    {
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(msg->observed_addr_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + msg->observed_addr_len;
    }

    // Field 5: protocol_version
    if (msg->protocol_version)
    {
        size_t proto_version_len = strlen(msg->protocol_version);
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(proto_version_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + proto_version_len;
    }

    // Field 6: agent_version
    if (msg->agent_version)
    {
        size_t agent_version_len = strlen(msg->agent_version);
        total_size += 1; // tag
        size_t len_varint_size = 0;
        uint8_t tmp[10];
        if (unsigned_varint_encode(agent_version_len, tmp, sizeof(tmp), &len_varint_size) != UNSIGNED_VARINT_OK)
            return -1;
        total_size += len_varint_size + agent_version_len;
    }

    if (total_size == 0)
    {
        // Empty message
        *out_buf = malloc(1);
        if (!*out_buf)
            return -1;
        *out_len = 0;
        return 0;
    }

    // Allocate buffer
    uint8_t *buf = malloc(total_size);
    if (!buf)
        return -1;

    size_t offset = 0;

    // Encode Field 1: public_key
    if (msg->public_key && msg->public_key_len > 0)
    {
        buf[offset++] = IDENTIFY_PUBLIC_KEY_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(msg->public_key_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->public_key, msg->public_key_len);
        offset += msg->public_key_len;
    }

    // Encode Field 2: listen_addrs (repeated)
    for (size_t i = 0; i < msg->num_listen_addrs; i++)
    {
        if (msg->listen_addrs[i] && msg->listen_addrs_lens[i] > 0)
        {
            buf[offset++] = IDENTIFY_LISTEN_ADDRS_TAG;
            size_t len_varint_size = 0;
            if (unsigned_varint_encode(msg->listen_addrs_lens[i], buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
            {
                free(buf);
                return -1;
            }
            offset += len_varint_size;
            memcpy(buf + offset, msg->listen_addrs[i], msg->listen_addrs_lens[i]);
            offset += msg->listen_addrs_lens[i];
        }
    }

    // Encode Field 3: protocols (repeated)
    for (size_t i = 0; i < msg->num_protocols; i++)
    {
        if (msg->protocols[i])
        {
            size_t proto_len = strlen(msg->protocols[i]);
            buf[offset++] = IDENTIFY_PROTOCOLS_TAG;
            size_t len_varint_size = 0;
            if (unsigned_varint_encode(proto_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
            {
                free(buf);
                return -1;
            }
            offset += len_varint_size;
            memcpy(buf + offset, msg->protocols[i], proto_len);
            offset += proto_len;
        }
    }

    // Encode Field 4: observed_addr
    if (msg->observed_addr && msg->observed_addr_len > 0)
    {
        buf[offset++] = IDENTIFY_OBSERVED_ADDR_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(msg->observed_addr_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->observed_addr, msg->observed_addr_len);
        offset += msg->observed_addr_len;
    }

    // Encode Field 5: protocol_version
    if (msg->protocol_version)
    {
        size_t proto_version_len = strlen(msg->protocol_version);
        buf[offset++] = IDENTIFY_PROTOCOL_VERSION_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(proto_version_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->protocol_version, proto_version_len);
        offset += proto_version_len;
    }

    // Encode Field 6: agent_version
    if (msg->agent_version)
    {
        size_t agent_version_len = strlen(msg->agent_version);
        buf[offset++] = IDENTIFY_AGENT_VERSION_TAG;
        size_t len_varint_size = 0;
        if (unsigned_varint_encode(agent_version_len, buf + offset, total_size - offset, &len_varint_size) != UNSIGNED_VARINT_OK)
        {
            free(buf);
            return -1;
        }
        offset += len_varint_size;
        memcpy(buf + offset, msg->agent_version, agent_version_len);
        offset += agent_version_len;
    }

    *out_buf = buf;
    *out_len = offset;
    return 0;
}

void libp2p_identify_free(libp2p_identify_t *msg)
{
    if (msg)
    {
        free(msg->public_key);
        free(msg->listen_addrs);
        free(msg->observed_addr);
        free(msg->protocols);
        free(msg->protocol_version);
        free(msg->agent_version);
        free(msg);
    }
}

/* ===== High-Level Protocol Handler Implementation ===== */

/**
 * @brief Internal context for identify request handling.
 */
typedef struct
{
    libp2p_identify_request_handler_t request_handler;
    void *user_data;
} libp2p_identify_handler_ctx_t;

/**
 * @brief Protocol handler for incoming identify streams.
 *
 * @param stream Protocol stream
 * @param user_data Handler context
 * @return 0 on success, negative on error
 */
static int identify_protocol_handler(libp2p_stream_t *stream, void *user_data)
{
    libp2p_identify_handler_ctx_t *ctx = (libp2p_identify_handler_ctx_t *)user_data;

    // For identify, we expect an empty request (just the protocol negotiation)
    // and we should respond with our identify information

    libp2p_identify_t response = {0};

    // Call user's request handler to populate the response
    if (ctx->request_handler)
    {
        const peer_id_t *local_peer = libp2p_stream_remote_peer(stream);    // This gets remote, we need local
        int result = ctx->request_handler(NULL, &response, ctx->user_data); // TODO: pass actual local peer
        if (result != 0)
        {
            return result;
        }
    }
    else
    {
        // Default response - minimal identify info
        response.protocol_version = strdup("ipfs/0.1.0");
        response.agent_version = strdup("c-libp2p/0.1.0");

        // Use a minimal placeholder since we don't have the real key
        // In practice, users should register their own handler
        response.public_key_len = 1 + 1 + 1 + 1 + 33; // tag + KeyType + tag + len + key_data
        response.public_key = malloc(response.public_key_len);
        if (!response.public_key)
        {
            return -1;
        }

        uint8_t *pk_ptr = response.public_key;
        *pk_ptr++ = 0x08;         // tag for KeyType field (field 1, varint)
        *pk_ptr++ = 0x02;         // KeyType = Secp256k1
        *pk_ptr++ = 0x12;         // tag for Data field (field 2, length-delimited)
        *pk_ptr++ = 0x21;         // length = 33 bytes for compressed secp256k1
        memset(pk_ptr, 0x42, 33); // Placeholder key data - users should override this
    }

    // Encode the response
    uint8_t *encoded_data = NULL;
    size_t encoded_len = 0;
    if (libp2p_identify_message_encode(&response, &encoded_data, &encoded_len) != 0)
    {
        // Free individual fields on error (don't call libp2p_identify_free on stack struct)
        if (response.protocol_version)
            free(response.protocol_version);
        if (response.agent_version)
            free(response.agent_version);
        if (response.public_key)
            free(response.public_key);
        if (response.listen_addrs)
            free(response.listen_addrs);
        if (response.observed_addr)
            free(response.observed_addr);
        if (response.protocols)
            free(response.protocols);
        return -1;
    }

    // Send the response with length prefix (required for libp2p protocol)
    // First send the length as varint
    uint8_t varint_buf[10];
    size_t varint_len = 0;
    if (unsigned_varint_encode(encoded_len, varint_buf, sizeof(varint_buf), &varint_len) != UNSIGNED_VARINT_OK)
    {
        // Cleanup allocated data
        free(encoded_data);
        // Free individual fields that were allocated (don't call libp2p_identify_free on stack struct)
        if (response.protocol_version)
            free(response.protocol_version);
        if (response.agent_version)
            free(response.agent_version);
        if (response.public_key)
            free(response.public_key);
        if (response.listen_addrs)
            free(response.listen_addrs);
        if (response.observed_addr)
            free(response.observed_addr);
        if (response.protocols)
            free(response.protocols);
        return -1;
    }

    // Send length prefix
    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)stream->ctx;
    if (libp2p_mplex_stream_send(mx, stream->stream_id, stream->initiator, varint_buf, varint_len) != LIBP2P_MPLEX_OK)
    {
        // Cleanup allocated data
        free(encoded_data);
        // Free individual fields that were allocated (don't call libp2p_identify_free on stack struct)
        if (response.protocol_version)
            free(response.protocol_version);
        if (response.agent_version)
            free(response.agent_version);
        if (response.public_key)
            free(response.public_key);
        if (response.listen_addrs)
            free(response.listen_addrs);
        if (response.observed_addr)
            free(response.observed_addr);
        if (response.protocols)
            free(response.protocols);
        return -1;
    }

    // Send the actual data
    if (libp2p_mplex_stream_send(mx, stream->stream_id, stream->initiator, encoded_data, encoded_len) != LIBP2P_MPLEX_OK)
    {
        // Cleanup allocated data
        free(encoded_data);
        // Free individual fields that were allocated (don't call libp2p_identify_free on stack struct)
        if (response.protocol_version)
            free(response.protocol_version);
        if (response.agent_version)
            free(response.agent_version);
        if (response.public_key)
            free(response.public_key);
        if (response.listen_addrs)
            free(response.listen_addrs);
        if (response.observed_addr)
            free(response.observed_addr);
        if (response.protocols)
            free(response.protocols);
        return -1;
    }

    ssize_t bytes_sent = varint_len + encoded_len;

    // Cleanup allocated data
    free(encoded_data);

    // Free individual fields that were allocated (don't call libp2p_identify_free on stack struct)
    if (response.protocol_version)
        free(response.protocol_version);
    if (response.agent_version)
        free(response.agent_version);
    if (response.public_key)
        free(response.public_key);
    if (response.listen_addrs)
        free(response.listen_addrs);
    if (response.observed_addr)
        free(response.observed_addr);
    if (response.protocols)
        free(response.protocols);

    return (bytes_sent == (ssize_t)encoded_len + varint_len) ? 0 : -1;
}

int libp2p_identify_register_handler(libp2p_protocol_handler_registry_t *registry, libp2p_identify_request_handler_t request_handler, void *user_data)
{
    if (!registry)
    {
        return -1;
    }

    // Create handler context
    libp2p_identify_handler_ctx_t *ctx = malloc(sizeof(libp2p_identify_handler_ctx_t));
    if (!ctx)
    {
        return -1;
    }

    ctx->request_handler = request_handler;
    ctx->user_data = user_data;

    // Register the protocol handler
    int result = libp2p_register_protocol_handler(registry, LIBP2P_IDENTIFY_PROTO_ID, identify_protocol_handler, ctx);

    if (result != 0)
    {
        free(ctx);
        return result;
    }

    return 0;
}

int libp2p_identify_send_request_with_context(libp2p_protocol_handler_ctx_t *handler_ctx, libp2p_identify_response_handler_t response_handler,
                                              void *user_data)
{
    if (!handler_ctx || !handler_ctx->uconn || !handler_ctx->muxer_ctx)
    {
        return -1;
    }

    // Pause protocol handler to avoid mplex frame contention during dial
    libp2p_protocol_handler_stop(handler_ctx);

    // Open stream for identify protocol using the existing mplex context
    libp2p_stream_t *stream = NULL;
    int result =
        libp2p_protocol_open_stream_with_context((libp2p_mplex_ctx_t *)handler_ctx->muxer_ctx, handler_ctx->uconn, LIBP2P_IDENTIFY_PROTO_ID, &stream);
    if (result != 0)
    {
        return result;
    }

    // For identify protocol, we don't send a request body - the protocol negotiation is the request
    // Just wait for the response
    libp2p_mplex_ctx_t *mx = (libp2p_mplex_ctx_t *)stream->ctx;

    uint8_t response_buf[4096]; // Buffer for identify response
    // Read length-prefixed identify response
    int msg_len = recv_length_prefixed_message(mx, stream->stream_id, stream->initiator, (char *)response_buf, sizeof(response_buf));
    if (msg_len <= 0)
    {
        libp2p_stream_free(stream);
        // Resume protocol handler before returning
        libp2p_protocol_handler_start(handler_ctx);
        return -1;
    }
    ssize_t bytes_read = msg_len;

    // Decode the response
    libp2p_identify_t *response = NULL;
    if (libp2p_identify_message_decode(response_buf, (size_t)bytes_read, &response) != 0)
    {
        libp2p_stream_free(stream);
        // Resume protocol handler before returning
        libp2p_protocol_handler_start(handler_ctx);
        return -1;
    }

    // Call the response handler
    int handler_result = 0;
    if (response_handler)
    {
        const peer_id_t *remote_peer = libp2p_stream_remote_peer(stream);
        handler_result = response_handler(remote_peer, response, user_data);
    }

    // Cleanup
    libp2p_identify_free(response);
    libp2p_stream_close(stream);
    libp2p_stream_free(stream);

    // Resume protocol handler thread
    libp2p_protocol_handler_start(handler_ctx);
    return handler_result;
}
