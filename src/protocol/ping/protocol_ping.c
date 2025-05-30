#include "protocol/ping/protocol_ping.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#else
#include <stdlib.h>
#endif

#ifndef NOW_MONO_MS_DECLARED
#include <time.h>
static inline uint64_t now_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}
#define NOW_MONO_MS_DECLARED 1
#endif

static int get_random_bytes(void *buf, size_t len)
{
#if defined(__linux__)
    ssize_t r = getrandom(buf, len, 0);
    if (r == (ssize_t)len)
        return 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t total = 0;
    while (total < len)
    {
        ssize_t n = read(fd, (char *)buf + total, len - total);
        if (n <= 0)
        {
            close(fd);
            return -1;
        }
        total += n;
    }
    close(fd);
    return 0;
#elif defined(_WIN32)
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
#else
    arc4random_buf(buf, len);
    return 0;
#endif
}

static inline libp2p_ping_err_t map_conn_err(ssize_t v)
{
    switch ((libp2p_conn_err_t)v)
    {
        case LIBP2P_CONN_ERR_TIMEOUT:
            return LIBP2P_PING_ERR_TIMEOUT;
        case LIBP2P_CONN_ERR_AGAIN:
            return LIBP2P_PING_ERR_IO;
        case LIBP2P_CONN_ERR_EOF:
        case LIBP2P_CONN_ERR_CLOSED:
        case LIBP2P_CONN_ERR_INTERNAL:
        default:
            return LIBP2P_PING_ERR_IO;
    }
}

static libp2p_ping_err_t conn_write_all(libp2p_conn_t *c, const uint8_t *buf, size_t len)
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
        return map_conn_err(n);
    }
    return LIBP2P_PING_OK;
}

static libp2p_ping_err_t conn_read_exact(libp2p_conn_t *c, uint8_t *buf, size_t len)
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
    return LIBP2P_PING_OK;
}

libp2p_ping_err_t libp2p_ping_roundtrip(libp2p_conn_t *conn, uint64_t timeout_ms, uint64_t *rtt_ms)
{
    if (!conn)
    {
        return LIBP2P_PING_ERR_NULL_PTR;
    }

    uint8_t payload[32];
    if (get_random_bytes(payload, sizeof(payload)) != 0)
    {
        return LIBP2P_PING_ERR_IO;
    }

    if (timeout_ms)
    {
        libp2p_conn_set_deadline(conn, timeout_ms);
    }

    uint64_t start = now_mono_ms();
    libp2p_ping_err_t rc = conn_write_all(conn, payload, sizeof(payload));
    if (rc != LIBP2P_PING_OK)
    {
        libp2p_conn_set_deadline(conn, 0);
        return rc;
    }
    
    uint8_t echo[32];
    rc = conn_read_exact(conn, echo, sizeof(echo));
    libp2p_conn_set_deadline(conn, 0);
    if (rc != LIBP2P_PING_OK) {
        return rc;
    }
    
    if (memcmp(payload, echo, sizeof(payload)) != 0) {
        return LIBP2P_PING_ERR_UNEXPECTED;
    }
    
    if (rtt_ms)
    {
        *rtt_ms = now_mono_ms() - start;
    }
    return LIBP2P_PING_OK;
}

libp2p_ping_err_t libp2p_ping_serve(libp2p_conn_t *conn)
{
    if (!conn)
    {
        return LIBP2P_PING_ERR_NULL_PTR;
    }
    uint8_t buf[32];
    for (;;)
    {
        libp2p_ping_err_t rc = conn_read_exact(conn, buf, sizeof(buf));
        if (rc != LIBP2P_PING_OK)
        {
            /* EOF means remote closed write end - stop gracefully */
            if (rc == LIBP2P_PING_ERR_IO)
            {
                return rc;
            }
            return LIBP2P_PING_OK;
        }
        rc = conn_write_all(conn, buf, sizeof(buf));
        if (rc != LIBP2P_PING_OK)
        {
            return rc;
        }
    }
}
