#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> /* usleep() */

#include "multiformats/multiaddr/multiaddr.h"
#include "protocol/tcp/protocol_tcp.h"
#include "transport/connection.h"
#include "transport/listener.h"
#include "transport/transport.h"

static void print_standard(const char *test_name, const char *details, int passed)
{
    if (passed)
        printf("TEST: %-70s | PASS\n", test_name);
    else
        printf("TEST: %-70s | FAIL: %s\n", test_name, details);
}

static int failures = 0;
#define TEST_OK(name, cond, fmt, ...)                                                                                                                \
    do                                                                                                                                               \
    {                                                                                                                                                \
        if (cond)                                                                                                                                    \
            print_standard(name, "", 1);                                                                                                             \
        else                                                                                                                                         \
        {                                                                                                                                            \
            char _details[256];                                                                                                                      \
            snprintf(_details, sizeof(_details), fmt, ##__VA_ARGS__);                                                                                \
            print_standard(name, _details, 0);                                                                                                       \
            failures++;                                                                                                                              \
        }                                                                                                                                            \
    } while (0)

static int accept_with_timeout(libp2p_listener_t *lst, libp2p_conn_t **out, int attempts, int sleep_us)
{
    int rc = LIBP2P_LISTENER_ERR_AGAIN;
    for (int i = 0; i < attempts; i++)
    {
        rc = libp2p_listener_accept(lst, out);
        if (rc == 0)
            return 0;
        if (rc != LIBP2P_LISTENER_ERR_AGAIN)
            return rc; /* hard failure */
        usleep(sleep_us);
    }
    return rc;
}

static void test_default_config_values(void)
{
    libp2p_tcp_config_t d = libp2p_tcp_config_default();
    const int ok = d.nodelay && d.reuse_port && d.keepalive && d.recv_buffer == 0 && d.send_buffer == 0 && d.listen_backlog == 128 && d.ttl_ms == 0;
    TEST_OK("Default config values", ok, "Unexpected field(s) in libp2p_tcp_config_default()");
}

static void test_transport_allocation(void)
{
    libp2p_transport_t *t1 = libp2p_tcp_transport_new(NULL);
    TEST_OK("Transport allocation (default cfg)", t1 != NULL, "returned NULL");

    libp2p_tcp_config_t c = {
        .nodelay = false, .reuse_port = false, .keepalive = false, .recv_buffer = 128 * 1024, .send_buffer = 256 * 1024, .listen_backlog = 8, .ttl_ms = 64};
    libp2p_transport_t *t2 = libp2p_tcp_transport_new(&c);
    TEST_OK("Transport allocation (custom cfg)", t2 != NULL, "returned NULL");

    libp2p_transport_free(t1);
    libp2p_transport_free(t2);
}

static void test_end_to_end(void)
{
    int port_base = 4001 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port_base);

    int err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr_new_from_str(valid)", addr && err == 0, "failed to parse \"%s\" (err=%d)", addr_str, err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("Listener creation", rc == 0 && lst, "libp2p_transport_listen() rc=%d", rc);
    libp2p_conn_t *cli = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli);
    TEST_OK("Dial succeeds", rc == 0 && cli, "libp2p_transport_dial() rc=%d", rc);
    libp2p_conn_t *srv = NULL;
    rc = accept_with_timeout(lst, &srv, /*attempts=*/100, /*sleep_us=*/2000);
    TEST_OK("Listener accept", rc == 0 && srv, "accept rc=%d", rc);

    const char ping[] = "ping-msg";
    (void)libp2p_conn_write(cli, ping, sizeof(ping));

    char buf[32] = {0};
    ssize_t n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(srv, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(2000);
    }
    TEST_OK("Payload: client → server", n == sizeof(ping) && memcmp(buf, ping, sizeof(ping)) == 0, "read %zd bytes (expected %zu)", n, sizeof(ping));

    const char pong[] = "pong-msg";
    (void)libp2p_conn_write(srv, pong, sizeof(pong));

    memset(buf, 0, sizeof(buf));
    n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(cli, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(2000);
    }
    TEST_OK("Payload: server → client", n == sizeof(pong) && memcmp(buf, pong, sizeof(pong)) == 0, "read %zd bytes (expected %zu)", n, sizeof(pong));

    libp2p_conn_t *cli2 = NULL, *srv2 = NULL;
    rc = libp2p_transport_dial(tcp, addr, &cli2);
    int ok_dial2 = (rc == 0 && cli2);
    rc = accept_with_timeout(lst, &srv2, 100, 2000);
    int ok_acc2 = (rc == 0 && srv2);
    TEST_OK("Second dial/accept", ok_dial2 && ok_acc2, "dial2=%d accept2=%d", ok_dial2, ok_acc2);

    const char msg2[] = "second-conn";
    (void)libp2p_conn_write(cli2, msg2, sizeof(msg2));
    memset(buf, 0, sizeof(buf));
    n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(srv2, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(2000);
    }
    TEST_OK("Second connection data integrity", n == sizeof(msg2) && memcmp(buf, msg2, sizeof(msg2)) == 0, "read %zd bytes (expected %zu)", n,
            sizeof(msg2));

    libp2p_conn_close(cli);
    libp2p_conn_close(srv);
    libp2p_conn_close(cli2);
    libp2p_conn_close(srv2);

    libp2p_conn_free(cli);
    libp2p_conn_free(srv);
    libp2p_conn_free(cli2);
    libp2p_conn_free(srv2);

    /* Close the listener before destroying the transport */
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);

    multiaddr_free(addr);
}

static void test_dns4_dial(void)
{
    int port_base = 5001 + (rand() % 1000);
    char ip_addr[64], dns_addr[64];
    snprintf(ip_addr, sizeof ip_addr, "/ip4/127.0.0.1/tcp/%d", port_base);
    snprintf(dns_addr, sizeof dns_addr, "/dns4/localhost/tcp/%d", port_base);

    int err = 0;
    multiaddr_t *ip_ma = multiaddr_new_from_str(ip_addr, &err);
    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, ip_ma, &lst);
    TEST_OK("DNS4 test: Listener creation", rc == 0 && lst, "rc=%d", rc);

    multiaddr_t *dns_ma = multiaddr_new_from_str(dns_addr, &err);
    libp2p_conn_t *cli = NULL, *srv = NULL;
    rc = libp2p_transport_dial(tcp, dns_ma, &cli);
    TEST_OK("DNS4 test: Dial by hostname", rc == 0 && cli, "rc=%d", rc);

    rc = accept_with_timeout(lst, &srv, 100, 2000);
    TEST_OK("DNS4 test: Accept via DNS dial", rc == 0 && srv, "rc=%d", rc);

    const char ping[] = "dns-ping";
    libp2p_conn_write(cli, ping, sizeof(ping));
    char buf[32] = {0};
    ssize_t n = LIBP2P_CONN_ERR_AGAIN;
    for (int i = 0; i < 100 && n == LIBP2P_CONN_ERR_AGAIN; i++)
    {
        n = libp2p_conn_read(srv, buf, sizeof(buf));
        if (n == LIBP2P_CONN_ERR_AGAIN)
            usleep(2000);
    }
    TEST_OK("DNS4 test: payload", n == sizeof(ping) && !memcmp(buf, ping, sizeof(ping)), "read %zd bytes", n);

    multiaddr_free(ip_ma);
    multiaddr_free(dns_ma);
    libp2p_conn_close(cli);
    libp2p_conn_free(cli);
    libp2p_conn_close(srv);
    libp2p_conn_free(srv);
    /* Close the listener before freeing the transport */
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
}

static void test_invalid_multiaddr_parse(void)
{
    int err = 0;
    multiaddr_t *bad = multiaddr_new_from_str("/not/a/real/addr", &err);
    TEST_OK("multiaddr_new_from_str(invalid) → error", bad == NULL && err != 0, "expected parse failure (err=%d, ptr=%p)", err, (void *)bad);
}

static void test_listen_wrong_protocol(void)
{
    const char *udp_str = "/ip4/127.0.0.1/udp/5555";
    int err = 0;
    multiaddr_t *udp_addr = multiaddr_new_from_str(udp_str, &err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, udp_addr, &lst);

    TEST_OK("Listen on /udp/ address should fail", rc != 0, "unexpected success (rc=%d, lst=%p)", rc, (void *)lst);

    /* Close listener before freeing transport */
    libp2p_listener_close(lst);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
    multiaddr_free(udp_addr);
}

static void test_dial_unreachable(void)
{
    const char *unreach = "/ip4/127.0.0.1/tcp/1";
    int err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(unreach, &err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_conn_t *c = NULL;

    int64_t t0 = time(NULL);
    int rc = libp2p_transport_dial(tcp, addr, &c);
    int64_t t1 = time(NULL);

    int ok = 0;

    if (rc != 0 || c == NULL)
    {
        ok = ((t1 - t0) < 5);
    }
    else
    {
        const char ch = 'x';
        ssize_t w = libp2p_conn_write(c, &ch, 1);

        if (w < 0 && w != LIBP2P_CONN_ERR_AGAIN)
        {
            ok = 1;
        }
        else
        {
            char b;
            ssize_t r = LIBP2P_CONN_ERR_AGAIN;
            for (int i = 0; i < 50 && r == LIBP2P_CONN_ERR_AGAIN; i++)
            {
                r = libp2p_conn_read(c, &b, 1);
                if (r == LIBP2P_CONN_ERR_AGAIN)
                    usleep(2000);
            }
            ok = (r < 0 && r != LIBP2P_CONN_ERR_AGAIN);
        }
    }

    TEST_OK("Dial unreachable (should fail or become unusable)", ok, "rc=%d c=%p elapsed=%llds", rc, (void *)c, (long long)(t1 - t0));

    libp2p_conn_close(c);
    libp2p_conn_free(c);
    multiaddr_free(addr);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
}

static void test_listener_close_and_free(void)
{
    int port_base = 6001 + (rand() % 1000);
    char addr_str[64];
    snprintf(addr_str, sizeof(addr_str), "/ip4/127.0.0.1/tcp/%d", port_base);

    int err = 0;
    multiaddr_t *addr = multiaddr_new_from_str(addr_str, &err);
    TEST_OK("multiaddr_new_from_str for free test", addr && err == 0, "parse failed (err=%d)", err);

    libp2p_transport_t *tcp = libp2p_tcp_transport_new(NULL);
    libp2p_listener_t *lst = NULL;
    int rc = libp2p_transport_listen(tcp, addr, &lst);
    TEST_OK("Listener creation for free test", rc == LIBP2P_TRANSPORT_OK && lst, "rc=%d", rc);

    rc = libp2p_listener_close(lst);
    TEST_OK("Listener close (first)", rc == LIBP2P_LISTENER_OK, "rc=%d", rc);

    rc = libp2p_listener_close(lst);
    TEST_OK("Listener close (second)", rc == LIBP2P_LISTENER_ERR_CLOSED, "rc=%d", rc);

    libp2p_conn_t *dummy = NULL;
    rc = libp2p_listener_accept(lst, &dummy);
    TEST_OK("Accept after close", rc == LIBP2P_LISTENER_ERR_CLOSED, "rc=%d", rc);

    libp2p_listener_free(NULL);
    TEST_OK("Listener free handles NULL", 1, "");

    multiaddr_free(addr);
    libp2p_transport_close(tcp);
    libp2p_transport_free(tcp);
}

int main(void)
{
    srand((unsigned)time(NULL));

    test_default_config_values();
    test_transport_allocation();
    test_end_to_end();
    test_dns4_dial();
    test_invalid_multiaddr_parse();
    test_listen_wrong_protocol();
    test_listener_close_and_free();
    test_dial_unreachable();

    if (failures)
    {
        printf("\nSome tests failed - total failures: %d\n", failures);
        const char *hold = getenv("INSTRUMENTS_HOLD");
        if (hold && *hold)
        {
            int s = atoi(hold);
            if (s <= 0)
                s = 2; /* sensible default */
            sleep(s);
        }
        sleep(5); /* 5‑second grace period */
        return EXIT_FAILURE;
    }
    printf("\nAll TCP transport tests passed!\n");
    const char *hold = getenv("INSTRUMENTS_HOLD");
    if (hold && *hold)
    {
        int s = atoi(hold);
        if (s <= 0)
            s = 2; /* sensible default */
        sleep(s);
    }
    return EXIT_SUCCESS;
}