#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

#include "multiformats/multiaddr/multiaddr.h"
#include "transport/transport.h"
#include "transport/listener.h"
#include "transport/connection.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/multiselect/protocol_multiselect.h"

/* ------------------------------------------------------------------------- */
/*  Test parameters                                                          */
/* ------------------------------------------------------------------------- */

static const char *const g_proposals[] = {
    "/other/1.0.0",
    "/myproto/1.0.0",
    NULL};

static const char *const g_supported[] = {
    "/myproto/1.0.0",
    "/other/1.0.0",
    NULL};

static const char *g_dial_result   = NULL;
static char        g_listen_result[64] = {0};

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
    libp2p_multiselect_err_t rc = libp2p_multiselect_listen(s, g_supported, NULL, &accepted_heap);
    assert(rc == LIBP2P_MULTISELECT_OK);
    strncpy(g_listen_result, accepted_heap, sizeof(g_listen_result) - 1);
    free((void *)accepted_heap);
    return NULL;
}

/* ------------------------------------------------------------------------- */
/*  Main                                                                     */
/* ------------------------------------------------------------------------- */

int main(void)
{
    /* Build TCP transport */
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    assert(tcp);

    /* Prepare local multiaddr (use a high port unlikely to collide) */
    int ma_err;
    multiaddr_t *addr = multiaddr_new_from_str("/ip4/127.0.0.1/tcp/4011", &ma_err);
    assert(addr && ma_err == 0);

    /* Start listener */
    libp2p_listener_t *lst = NULL;
    assert(libp2p_transport_listen(tcp, addr, &lst) == LIBP2P_TRANSPORT_OK);

    /* Dial */
    libp2p_conn_t *c = NULL;
    assert(libp2p_transport_dial(tcp, addr, &c) == LIBP2P_TRANSPORT_OK);

    /* Accept (wait until ready) */
    libp2p_conn_t *s = NULL;
    while (libp2p_listener_accept(lst, &s) == LIBP2P_LISTENER_ERR_AGAIN) {}
    assert(s);

    /* Spawn threads */
    pthread_t tid_dial, tid_listen;
    assert(pthread_create(&tid_dial, NULL, dial_thread, c) == 0);
    assert(pthread_create(&tid_listen, NULL, listen_thread, s) == 0);

    pthread_join(tid_dial, NULL);
    pthread_join(tid_listen, NULL);

    /* Validate */
    assert(strcmp(g_dial_result, "/other/1.0.0") == 0);
    assert(strcmp(g_listen_result, "/other/1.0.0") == 0);

    printf("multiselect handshake successful: %s\n", g_dial_result);

    return 0;
}
