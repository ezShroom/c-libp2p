#ifndef LIBP2P_COMPAT_POLL_H
#define LIBP2P_COMPAT_POLL_H

/**
 * @file poll.h
 * @brief Minimal poll() replacement for Windows builds.
 *
 * This compatibility layer maps POSIX poll() calls to the Windows WSAPoll()
 * API so the existing code can compile unmodified. It only implements the
 * subset of functionality required by libp2p-c.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* Ensure WSAPoll is available */
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

/* Use the pollfd definition already provided by Winsock2 headers.
   Define nfds_t only if it is missing. */
#ifndef LIBP2P_NFDS_T_DEFINED
typedef unsigned long nfds_t; /* WSAPoll uses ULONG – this matches */
#define LIBP2P_NFDS_T_DEFINED 1
#endif

/* Event flag definitions (map directly to Winsock values when available) */
#ifndef POLLIN
#define POLLIN 0x0001
#endif
#ifndef POLLPRI
#define POLLPRI 0x0002
#endif
#ifndef POLLOUT
#define POLLOUT 0x0004
#endif
#ifndef POLLERR
#define POLLERR 0x0008
#endif
#ifndef POLLHUP
#define POLLHUP 0x0010
#endif
#ifndef POLLNVAL
#define POLLNVAL 0x0020
#endif

/** Function wrapper */

/** Wrap WSAPoll with a POSIX-like poll() API. */
static inline int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    return WSAPoll((WSAPOLLFD *)fds, (ULONG)nfds, timeout);
}

#else /* non-Windows */

#include_next <poll.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_POLL_H */