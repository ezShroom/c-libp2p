/**
 * @file arpa/inet.h
 * @brief Minimal Windows compatibility shim for <arpa/inet.h>.
 *
 * When compiling on Windows we include Winsock2 and Ws2tcpip which provide
 * the same networking primitives. On non-Windows platforms the real system
 * header is included via `#include_next` so behaviour stays unchanged.
 */

#ifndef LIBP2P_COMPAT_ARPA_INET_H
#define LIBP2P_COMPAT_ARPA_INET_H

#ifdef _WIN32

/* Ensure winsock is available */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

/* For inet_pton / inet_ntop we need at least Windows Vista */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

/* MinGW defines htonl/ntohl etc. in winsock2.h already. If additional
   POSIX names are required they can be added here. */

#else /* ! _WIN32 — fall back to the real POSIX header */

#include_next <arpa/inet.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_ARPA_INET_H */