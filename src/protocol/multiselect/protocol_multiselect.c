#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/multiselect/protocol_multiselect.h"

#define MS_MAX_MESSAGE_SIZE (64 * 1024 * 1024) /* 64 MiB sanity cap      */

static inline libp2p_multiselect_err_t map_conn_err(ssize_t v)
{
    switch ((libp2p_conn_err_t)v)
    {
        case LIBP2P_CONN_ERR_TIMEOUT:
            return LIBP2P_MULTISELECT_ERR_TIMEOUT;
        case LIBP2P_CONN_ERR_AGAIN:
            return LIBP2P_MULTISELECT_ERR_IO;
        case LIBP2P_CONN_ERR_EOF:
        case LIBP2P_CONN_ERR_CLOSED:
        case LIBP2P_CONN_ERR_INTERNAL:
        default:
            return LIBP2P_MULTISELECT_ERR_IO;
    }
}

static libp2p_multiselect_err_t conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    while (len)
    {
        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        { /* progress                      */
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            /* try again */
            continue;
        }
        return map_conn_err(n); /* any other error is fatal */
    }
    return LIBP2P_MULTISELECT_OK;
}

/* Read exactly len bytes, retrying on EAGAIN. */
static libp2p_multiselect_err_t conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
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
        {
            /* no data yet – spin */
            continue;
        }
        return map_conn_err(n); /* anything else is fatal */
    }
    return LIBP2P_MULTISELECT_OK;
}

static libp2p_multiselect_err_t send_msg(libp2p_conn_t *c, const char *msg)
{
    fprintf(stderr, "[MULTISELECT] >> %s\n", msg);
    if (!c || !msg)
    {
        return LIBP2P_MULTISELECT_ERR_NULL_PTR;
    }

    const size_t pl_no_nl = strlen(msg);
    const size_t pl_len = pl_no_nl + 1; /* include newline       */
    if (pl_len > MS_MAX_MESSAGE_SIZE)
    {
        return LIBP2P_MULTISELECT_ERR_PROTO_MAL;
    }

    uint8_t var[10];
    size_t vlen;
    if (unsigned_varint_encode((uint64_t)pl_len, var, sizeof(var), &vlen))
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }

    const size_t frame_len = vlen + pl_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame)
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }

    memcpy(frame, var, vlen);
    memcpy(frame + vlen, msg, pl_no_nl);
    frame[vlen + pl_no_nl] = '\n';

    libp2p_multiselect_err_t rc = conn_write_all(c, frame, frame_len);
    free(frame);
    return rc;
}

/* Send multiple messages in a single write. */
static libp2p_multiselect_err_t send_msg_batch(libp2p_conn_t *c, const char *const msgs[], size_t count)
{
    if (!c || !msgs)
    {
        return LIBP2P_MULTISELECT_ERR_NULL_PTR;
    }

    size_t total = 0;
    size_t lens[8];
    size_t vlen[8];
    uint8_t vars[8][10];
    if (count > 8)
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }
    for (size_t i = 0; i < count; ++i)
    {
        size_t mlen = strlen(msgs[i]) + 1;
        if (mlen > MS_MAX_MESSAGE_SIZE)
        {
            return LIBP2P_MULTISELECT_ERR_PROTO_MAL;
        }
        lens[i] = mlen;
        if (unsigned_varint_encode((uint64_t)mlen, vars[i], sizeof(vars[i]), &vlen[i]))
        {
            return LIBP2P_MULTISELECT_ERR_INTERNAL;
        }
        total += vlen[i] + mlen;
    }

    uint8_t *frame = (uint8_t *)malloc(total);
    if (!frame)
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }

    size_t off = 0;
    for (size_t i = 0; i < count; ++i)
    {
        memcpy(frame + off, vars[i], vlen[i]);
        off += vlen[i];
        memcpy(frame + off, msgs[i], lens[i] - 1);
        off += lens[i] - 1;
        frame[off++] = '\n';
    }

    libp2p_multiselect_err_t rc = conn_write_all(c, frame, total);
    free(frame);
    return rc;
}

/* reads a frame → returns heap string w/o “\n”; caller frees                */
static libp2p_multiselect_err_t recv_msg(libp2p_conn_t *c, char **out)
{
    if (!c || !out)
    {
        return LIBP2P_MULTISELECT_ERR_NULL_PTR;
    }

    uint8_t var[9];
    size_t used = 0;
    uint64_t pl_len = 0;
    while (true)
    {
        if (used == sizeof(var))
        {
            return LIBP2P_MULTISELECT_ERR_PROTO_MAL;
        }
        libp2p_multiselect_err_t r = conn_read_exact(c, &var[used], 1);
        if (r)
        {
            return r;
        }
        ++used;
        size_t dummy;
        if (unsigned_varint_decode(var, used, &pl_len, &dummy) == UNSIGNED_VARINT_OK)
        {
            break;
        }
    }

    if (!pl_len || pl_len > MS_MAX_MESSAGE_SIZE)
    {
        return LIBP2P_MULTISELECT_ERR_PROTO_MAL;
    }

    uint8_t *payload = (uint8_t *)malloc(pl_len);
    if (!payload)
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }

    libp2p_multiselect_err_t rc = conn_read_exact(c, payload, (size_t)pl_len);
    if (rc)
    {
        free(payload);
        return rc;
    }

    if (payload[pl_len - 1] != '\n')
    {
        free(payload);
        return LIBP2P_MULTISELECT_ERR_PROTO_MAL;
    }

    payload[pl_len - 1] = '\0'; /* strip newline              */
    *out = (char *)payload;
    fprintf(stderr, "[MULTISELECT] << %s\n", *out);
    return LIBP2P_MULTISELECT_OK;
}

static bool str_in_list(const char *needle, const char *const list[])
{
    for (size_t i = 0; list && list[i]; ++i)
    {
        if (strcmp(needle, list[i]) == 0)
        {
            return true;
        }
    }
    return false;
}

static libp2p_multiselect_err_t send_ls_response(libp2p_conn_t *c, const char *const supported[])
{
    size_t inner = 0;
    for (size_t i = 0; supported && supported[i]; ++i)
    {
        size_t m = strlen(supported[i]) + 1; /* +‘\n’          */
        inner += unsigned_varint_size(m) + m;
    }
    inner += 1; /* final ‘\n’    */

    uint8_t var[10];
    size_t vlen;
    if (unsigned_varint_encode((uint64_t)inner, var, sizeof(var), &vlen))
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }

    size_t frame_len = vlen + inner;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame)
    {
        return LIBP2P_MULTISELECT_ERR_INTERNAL;
    }

    size_t off = 0;
    memcpy(frame + off, var, vlen);
    off += vlen;

    for (size_t i = 0; supported && supported[i]; ++i)
    {
        size_t m = strlen(supported[i]) + 1;
        size_t vbytes = 0;
        unsigned_varint_encode((uint64_t)m, frame + off, frame_len - off, &vbytes);
        off += vbytes;
        memcpy(frame + off, supported[i], m - 1);
        off += m - 1;
        frame[off++] = '\n';
    }
    frame[off++] = '\n';

    libp2p_multiselect_err_t rc = conn_write_all(c, frame, frame_len);
    free(frame);
    return rc;
}

libp2p_multiselect_err_t libp2p_multiselect_dial(libp2p_conn_t *conn, const char *const proposals[], uint64_t timeout_ms, const char **accepted_out)
{
    if (!conn || !proposals)
    {
        return LIBP2P_MULTISELECT_ERR_NULL_PTR;
    }
    if (timeout_ms)
    {
        libp2p_conn_set_deadline(conn, timeout_ms);
    }

    const char *batch[2];
    size_t bcnt = 0;
    batch[bcnt++] = LIBP2P_MULTISELECT_PROTO_ID;
    bool have_proto0 = proposals[0] != NULL;
    if (have_proto0)
        batch[bcnt++] = proposals[0];

    libp2p_multiselect_err_t rc = send_msg_batch(conn, batch, bcnt);
    if (rc)
    {
        goto done;
    }

    char *msg = NULL;
    rc = recv_msg(conn, &msg);
    if (rc)
    {
        goto done;
    }
    if (strcmp(msg, LIBP2P_MULTISELECT_PROTO_ID) != 0)
    {
        free(msg);
        rc = LIBP2P_MULTISELECT_ERR_PROTO_MAL;
        goto done;
    }
    free(msg);

    rc = recv_msg(conn, &msg);
    if (rc)
    {
        goto done;
    }

    size_t idx = 0;

    if (!strcmp(msg, LIBP2P_MULTISELECT_NA))
    {
        free(msg);
        /* remote rejected proto0; try next */
        ++idx;
        if (!proposals[idx])
        {
            rc = LIBP2P_MULTISELECT_ERR_UNAVAIL;
            goto done;
        }
        rc = send_msg(conn, proposals[idx]);
        if (rc)
            goto done;
    }
    else if (have_proto0 && !strcmp(msg, proposals[0]))
    {
        if (accepted_out)
            *accepted_out = proposals[0];
        free(msg);
        rc = LIBP2P_MULTISELECT_OK;
        goto done;
    }
    else
    {
        free(msg);
        rc = LIBP2P_MULTISELECT_ERR_PROTO_MAL;
        goto done;
    }

    while (proposals[idx])
    {
        rc = recv_msg(conn, &msg);
        if (rc)
            goto done;

        if (!strcmp(msg, LIBP2P_MULTISELECT_PROTO_ID))
        {
            free(msg);
            continue;
        }
        if (!strcmp(msg, LIBP2P_MULTISELECT_NA))
        {
            free(msg);
            ++idx;
            if (!proposals[idx])
            {
                rc = LIBP2P_MULTISELECT_ERR_UNAVAIL;
                goto done;
            }
            rc = send_msg(conn, proposals[idx]);
            if (rc)
                goto done;
            continue;
        }

        if (!strcmp(msg, proposals[idx]))
        {
            if (accepted_out)
                *accepted_out = proposals[idx];
            free(msg);
            rc = LIBP2P_MULTISELECT_OK;
            goto done;
        }

        free(msg);
        rc = LIBP2P_MULTISELECT_ERR_PROTO_MAL;
        goto done;
    }

    rc = LIBP2P_MULTISELECT_ERR_UNAVAIL;

done:
    if (timeout_ms)
    {
        libp2p_conn_set_deadline(conn, 0); /* clear */
    }
    return rc;
}

libp2p_multiselect_err_t libp2p_multiselect_listen(libp2p_conn_t *conn, const char *const supported[], const libp2p_multiselect_config_t *cfg_opt,
                                                   const char **accepted_out)
{
    if (!conn || !supported)
    {
        return LIBP2P_MULTISELECT_ERR_NULL_PTR;
    }

    libp2p_multiselect_config_t cfg = cfg_opt ? *cfg_opt : libp2p_multiselect_config_default();

    if (cfg.handshake_timeout_ms)
    {
        libp2p_conn_set_deadline(conn, cfg.handshake_timeout_ms);
    }

    bool header_sent = false;
    bool header_received = false;
    libp2p_multiselect_err_t rc = LIBP2P_MULTISELECT_OK;

    for (;;)
    {
        char *msg = NULL;
        rc = recv_msg(conn, &msg);
        if (rc)
        {
            goto fail;
        }

        if (!header_received)
        {
            if (strcmp(msg, LIBP2P_MULTISELECT_PROTO_ID) != 0)
            {
                free(msg);
                rc = LIBP2P_MULTISELECT_ERR_PROTO_MAL;
                goto fail;
            }
            header_received = true;
            free(msg);
            if (!header_sent)
            {
                rc = send_msg(conn, LIBP2P_MULTISELECT_PROTO_ID);
                if (rc)
                {
                    goto fail;
                }
                header_sent = true;
            }
            continue;
        }

        /* multistream header */
        if (!strcmp(msg, LIBP2P_MULTISELECT_PROTO_ID))
        {
            free(msg);
            if (!header_sent)
            {
                rc = send_msg(conn, LIBP2P_MULTISELECT_PROTO_ID);
                if (rc)
                {
                    goto fail;
                }
                header_sent = true;
            }
            continue;
        }

        /* ls request */
        if (!strcmp(msg, LIBP2P_MULTISELECT_LS))
        {
            free(msg);
            rc = cfg.enable_ls ? send_ls_response(conn, supported) : send_msg(conn, LIBP2P_MULTISELECT_NA);
            if (rc)
            {
                goto fail;
            }
            continue; /* wait for choice */
        }

        /* protocol proposal */
        if (str_in_list(msg, supported))
        {
            rc = send_msg(conn, msg); /* echo */
            if (rc)
            {
                free(msg);
                goto fail;
            }

            if (accepted_out)
            {
                *accepted_out = msg; /* heap copy */
            }
            else
            {
                free(msg);
            }

            if (cfg.handshake_timeout_ms)
            {
                libp2p_conn_set_deadline(conn, 0); /* clear */
            }
            return LIBP2P_MULTISELECT_OK;
        }

        /* not available  */
        rc = send_msg(conn, LIBP2P_MULTISELECT_NA);
        free(msg);
        if (rc)
        {
            goto fail;
        }
        /* loop continues for another proposal */
    }

fail:
    if (cfg.handshake_timeout_ms)
    {
        libp2p_conn_set_deadline(conn, 0);
    }
    return rc;
}
