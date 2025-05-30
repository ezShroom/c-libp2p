#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/multiselect/protocol_multiselect.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "protocol/tcp/protocol_tcp.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

/* ------------------------------------------------------------------------- */
/*  Test parameters                                                          */
/* ------------------------------------------------------------------------- */

static const char *const g_proposals[] = {"/other/1.0.0", "/myproto/1.0.0", NULL};

static const char *const g_supported[] = {"/myproto/1.0.0", "/other/1.0.0", NULL};

static const char *g_dial_result = NULL;
static char g_listen_result[64] = {0};

/* ------------------------------------------------------------------------- */
/*  Helper utilities                                                         */
/* ------------------------------------------------------------------------- */

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
    {
        printf("TEST: %-50s | PASS\n", test_name);
    }
    else
    {
        printf("TEST: %-50s | FAIL: %s\n", test_name, details);
    }
}

static void conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
{
    while (len)
    {
        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        {
            buf += (size_t)n;
            len -= (size_t)n;
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
            continue;
        assert(0 && "conn_write failed");
    }
}

static void send_raw_msg(libp2p_conn_t *c, const char *msg)
{
    uint8_t var[10];
    const size_t payload_len = strlen(msg) + 1; /* include newline */
    size_t vlen;
    int rc = unsigned_varint_encode((uint64_t)payload_len, var, sizeof(var), &vlen);
    assert(rc == UNSIGNED_VARINT_OK);

    const size_t frame_len = vlen + payload_len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    assert(frame);
    memcpy(frame, var, vlen);
    memcpy(frame + vlen, msg, payload_len - 1);
    frame[vlen + payload_len - 1] = '\n';

    conn_write_all(c, frame, frame_len);
    free(frame);
}

/* ------------------------------------------------------------------------- */
/*  Dialer thread                                                            */
/* ------------------------------------------------------------------------- */

static void *dial_thread(void *arg)
{
    libp2p_conn_t *c = (libp2p_conn_t *)arg;
    const char *accepted = NULL;
    libp2p_multiselect_err_t rc = libp2p_multiselect_dial(c, g_proposals, 5000, &accepted);
    assert(rc == LIBP2P_MULTISELECT_OK);
    g_dial_result = accepted; /* pointer from proposals array */
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*  Listener thread                                                          */
/* ------------------------------------------------------------------------- */

static void *listen_thread(void *arg)
{
    libp2p_conn_t *s = (libp2p_conn_t *)arg;
    const char *accepted_heap = NULL;
    libp2p_multiselect_err_t rc =
        libp2p_multiselect_listen(s, g_supported, NULL, &accepted_heap);
    assert(rc == LIBP2P_MULTISELECT_OK);
    strncpy(g_listen_result, accepted_heap, sizeof(g_listen_result) - 1);
    free((void *)accepted_heap);
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*  Test cases                                                               */
/* ------------------------------------------------------------------------- */

static void test_handshake_success(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4011", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    pthread_t tid_dial, tid_listen;
    assert(pthread_create(&tid_dial, NULL, dial_thread, c) == 0);
    assert(pthread_create(&tid_listen, NULL, listen_thread, s) == 0);

    pthread_join(tid_dial, NULL);
    pthread_join(tid_listen, NULL);

    assert(strcmp(g_dial_result, "/other/1.0.0") == 0);
    assert(strcmp(g_listen_result, "/other/1.0.0") == 0);

    {
        char test_name[128];
        sprintf(test_name, "multiselect handshake successful: %s", g_dial_result);
        print_standard(test_name, "", 1);
    }

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

static void test_reject_missing_header(void)
{
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4012", &ma_err);
    assert(addr && ma_err == 0);

    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN)
        ;
    assert(s);

    /* Send invalid message before the multistream header */
    send_raw_msg(s, "ls");

    const char *accepted = NULL;
    libp2p_multiselect_err_t rc =
        libp2p_multiselect_dial(c, g_proposals, 1000, &accepted);
    assert(rc == LIBP2P_MULTISELECT_ERR_PROTO_MAL);

    print_standard("multiselect handshake aborted on invalid header", "", 1);

    libp2p_conn_close(c);
    libp2p_conn_close(s);
    libp2p_conn_free(c);
    libp2p_conn_free(s);

    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    multiaddr_free(addr);
    libp2p_transport_free(tcp);
}

/* ------------------------------------------------------------------------- */
/*  Main                                                                     */
/* ------------------------------------------------------------------------- */

int main(void)
{
    test_handshake_success();
    test_reject_missing_header();
    return 0;
}
