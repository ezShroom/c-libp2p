#include "protocol/noise/protocol_noise_conn.h"
#include <noise/protocol/constants.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol/noise/protocol_noise_extensions.h"
typedef struct noise_conn_ctx
{
    libp2p_conn_t *raw;
    NoiseCipherState *send;
    NoiseCipherState *recv;
    uint8_t *buf;
    size_t buf_len;
    size_t buf_pos;
    uint8_t *early_data;
    size_t early_data_len;
    uint8_t *extensions;
    size_t extensions_len;
    noise_extensions_t *parsed_ext;
    size_t max_plaintext;
    uint64_t send_count;
    uint64_t recv_count;
} noise_conn_ctx_t;

static ssize_t noise_conn_read(libp2p_conn_t *c, void *buf, size_t len)
{
    noise_conn_ctx_t *ctx = c->ctx;
    if (ctx->recv_count == UINT64_MAX)
    {
        libp2p_conn_close(ctx->raw);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    if (ctx->buf_len > ctx->buf_pos)
    {
        size_t avail = ctx->buf_len - ctx->buf_pos;
        size_t n = len < avail ? len : avail;
        memcpy(buf, ctx->buf + ctx->buf_pos, n);
        ctx->buf_pos += n;
        if (ctx->buf_pos == ctx->buf_len)
        {
            free(ctx->buf);
            ctx->buf = NULL;
            ctx->buf_len = ctx->buf_pos = 0;
        }
        return (ssize_t)n;
    }

    uint8_t hdr[2];
    ssize_t r = libp2p_conn_read(ctx->raw, hdr, 2);
    if (r != 2)
        return r < 0 ? r : LIBP2P_CONN_ERR_EOF;
    uint16_t mlen = ((uint16_t)hdr[0] << 8) | hdr[1];
    uint8_t *cipher = malloc(mlen);
    if (!cipher)
        return LIBP2P_CONN_ERR_INTERNAL;
    r = libp2p_conn_read(ctx->raw, cipher, mlen);
    if (r != mlen)
    {
        free(cipher);
        return r < 0 ? r : LIBP2P_CONN_ERR_EOF;
    }
    NoiseBuffer nb;
    noise_buffer_set_input(nb, cipher, mlen);
    int err = noise_cipherstate_decrypt(ctx->recv, &nb);
    if (err == NOISE_ERROR_INVALID_NONCE)
    {
        free(cipher);
        libp2p_conn_close(ctx->raw);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    if (err != NOISE_ERROR_NONE)
    {
        free(cipher);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    ctx->recv_count++;
    size_t max_plain = ctx->max_plaintext ? ctx->max_plaintext : NOISE_MAX_PAYLOAD_LEN;
    if (nb.size > max_plain)
    {
        free(cipher);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    ctx->buf = malloc(nb.size);
    if (!ctx->buf)
    {
        free(cipher);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    memcpy(ctx->buf, nb.data, nb.size);
    free(cipher);
    ctx->buf_len = nb.size;
    ctx->buf_pos = 0;
    size_t n = len < nb.size ? len : nb.size;
    memcpy(buf, ctx->buf, n);
    ctx->buf_pos = n;
    if (ctx->buf_pos == ctx->buf_len)
    {
        free(ctx->buf);
        ctx->buf = NULL;
        ctx->buf_len = ctx->buf_pos = 0;
    }
    return (ssize_t)n;
}

static ssize_t noise_conn_write(libp2p_conn_t *c, const void *buf, size_t len)
{
    noise_conn_ctx_t *ctx = c->ctx;
    if (ctx->send_count == UINT64_MAX)
    {
        libp2p_conn_close(ctx->raw);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    size_t mac_len = noise_cipherstate_get_mac_length(ctx->send);
    size_t max_allowed = NOISE_MAX_PAYLOAD_LEN - mac_len;
    size_t limit = ctx->max_plaintext && ctx->max_plaintext < max_allowed ? ctx->max_plaintext : max_allowed;
    if (len > limit)
        return LIBP2P_CONN_ERR_INTERNAL;
    uint16_t mlen = (uint16_t)(len + mac_len);
    uint8_t *out = malloc(mlen + 2);
    if (!out)
        return LIBP2P_CONN_ERR_INTERNAL;
    memcpy(out + 2, buf, len);
    NoiseBuffer nb;
    noise_buffer_set_inout(nb, out + 2, len, mlen);
    int err = noise_cipherstate_encrypt(ctx->send, &nb);
    if (err == NOISE_ERROR_INVALID_NONCE)
    {
        free(out);
        libp2p_conn_close(ctx->raw);
        return LIBP2P_CONN_ERR_CLOSED;
    }
    if (err != NOISE_ERROR_NONE)
    {
        free(out);
        return LIBP2P_CONN_ERR_INTERNAL;
    }
    out[0] = (uint8_t)(nb.size >> 8);
    out[1] = (uint8_t)nb.size;
    ssize_t rc = libp2p_conn_write(ctx->raw, out, nb.size + 2);
    free(out);
    if (rc != nb.size + 2)
        return rc < 0 ? rc : LIBP2P_CONN_ERR_INTERNAL;
    ctx->send_count++;
    return (ssize_t)len;
}

static libp2p_conn_err_t noise_conn_set_deadline(libp2p_conn_t *c, uint64_t ms)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_set_deadline(ctx->raw, ms);
}

static const multiaddr_t *noise_conn_local(libp2p_conn_t *c)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_local_addr(ctx->raw);
}

static const multiaddr_t *noise_conn_remote(libp2p_conn_t *c)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_remote_addr(ctx->raw);
}

const uint8_t *noise_conn_get_early_data(const libp2p_conn_t *c, size_t *len)
{
    if (!c)
        return NULL;
    noise_conn_ctx_t *ctx = c->ctx;
    if (len)
        *len = ctx->early_data_len;
    return ctx->early_data;
}

const uint8_t *noise_conn_get_extensions(const libp2p_conn_t *c, size_t *len)
{
    if (!c)
        return NULL;
    noise_conn_ctx_t *ctx = c->ctx;
    if (len)
        *len = ctx->extensions_len;
    return ctx->extensions;
}

const noise_extensions_t *noise_conn_get_parsed_extensions(const libp2p_conn_t *c)
{
    if (!c)
        return NULL;
    noise_conn_ctx_t *ctx = c->ctx;
    return ctx->parsed_ext;
}

static libp2p_conn_err_t noise_conn_close(libp2p_conn_t *c)
{
    noise_conn_ctx_t *ctx = c->ctx;
    return libp2p_conn_close(ctx->raw);
}

static void noise_conn_free(libp2p_conn_t *c)
{
    if (!c)
        return;
    noise_conn_ctx_t *ctx = c->ctx;
    if (ctx)
    {
        noise_cipherstate_free(ctx->send);
        noise_cipherstate_free(ctx->recv);
        libp2p_conn_free(ctx->raw);
        free(ctx->buf);
        free(ctx->early_data);
        free(ctx->extensions);
        noise_extensions_free(ctx->parsed_ext);
        free(ctx);
    }
    free(c);
}

static const libp2p_conn_vtbl_t NOISE_CONN_VTBL = {
    .read = noise_conn_read,
    .write = noise_conn_write,
    .set_deadline = noise_conn_set_deadline,
    .local_addr = noise_conn_local,
    .remote_addr = noise_conn_remote,
    .close = noise_conn_close,
    .free = noise_conn_free,
};

libp2p_conn_t *make_noise_conn(libp2p_conn_t *raw, NoiseCipherState *send, NoiseCipherState *recv, size_t max_plaintext, uint8_t *early_data,
                               size_t early_data_len, uint8_t *extensions, size_t extensions_len, noise_extensions_t *parsed_ext)
{
    if (!raw || !send || !recv)
        return NULL;
    noise_conn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->raw = raw;
    ctx->send = send;
    ctx->recv = recv;
    ctx->max_plaintext = max_plaintext;
    ctx->send_count = 0;
    ctx->recv_count = 0;
    ctx->early_data = early_data;
    ctx->early_data_len = early_data_len;
    ctx->extensions = extensions;
    ctx->extensions_len = extensions_len;
    ctx->parsed_ext = parsed_ext;
    libp2p_conn_t *c = calloc(1, sizeof(*c));
    if (!c)
    {
        free(ctx);
        return NULL;
    }
    c->vt = &NOISE_CONN_VTBL;
    c->ctx = ctx;
    return c;
}
