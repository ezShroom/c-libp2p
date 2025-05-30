#ifndef LIBP2P_COMPAT_NETDB_H
#define LIBP2P_COMPAT_NETDB_H

/**
 * @file netdb.h
 * @brief Minimal <netdb.h> replacement for Windows builds.
 *
 * The c-libp2p codebase only uses getaddrinfo()/freeaddrinfo() and the
 * addrinfo structure, all of which are already provided by <ws2tcpip.h>
 * on modern Windows systems.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

/* Ensure the newer Winsock2 APIs (getaddrinfo etc.) are available. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* Vista / Server 2008 */
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

/* POSIX names expect gai_strerror() returning const char *.  ws2tcpip offers
   gai_strerrorA/W.  Provide an alias if the ANSI version is present. */
#if !defined(gai_strerror) && defined(gai_strerrorA)
#define gai_strerror gai_strerrorA
#endif

/* Likewise, EAI_* constants are already defined by ws2tcpip.h. */

#else /* Non-Windows platforms – use the real header. */

#include_next <netdb.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_NETDB_H */