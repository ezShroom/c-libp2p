#include "transport/conn_util.h"
#include <time.h>
#include <errno.h>
#include <unistd.h>

/* Internal helper: nano-sleep for ~1ms on busy loops */
static inline void tiny_sleep(void)
{
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000L }; /* 1ms */
    nanosleep(&ts, NULL);
}

libp2p_conn_err_t libp2p_conn_write_all(libp2p_conn_t *c,
                                        const uint8_t *buf,
                                        size_t len,
                                        uint64_t slow_ms)
{
    if (!c || !buf)
        return LIBP2P_CONN_ERR_NULL_PTR;

    if (slow_ms == 0)
        slow_ms = 1000; /* default 1 s */

    uint64_t start = now_mono_ms();

    while (len)
    {
        ssize_t n = libp2p_conn_write(c, buf, len);
        if (n > 0)
        {
            buf  += (size_t)n;
            len  -= (size_t)n;
            start = now_mono_ms();
            continue;
        }
        if (n == LIBP2P_CONN_ERR_AGAIN)
        {
            if (now_mono_ms() - start > slow_ms)
                return LIBP2P_CONN_ERR_TIMEOUT;
            tiny_sleep();
            continue;
        }
        return (libp2p_conn_err_t)n; /* propagate EOF / CLOSED / INTERNAL */
    }
    return LIBP2P_CONN_OK;
}

libp2p_conn_err_t libp2p_conn_read_exact(libp2p_conn_t *c,
                                         uint8_t *buf,
                                         size_t len)
{
    if (!c || !buf)
        return LIBP2P_CONN_ERR_NULL_PTR;

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
            /* Busy wait – assume caller set a deadline on the connection. */
            tiny_sleep();
            continue;
        }
        return (libp2p_conn_err_t)n; /* bubble up real error */
    }
    return LIBP2P_CONN_OK;
}
