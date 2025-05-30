#ifndef LIBP2P_COMPAT_NETINET_IN_H
#define LIBP2P_COMPAT_NETINET_IN_H

/**
 * @file netinet/in.h
 * @brief Minimal <netinet/in.h> replacement for Windows builds.
 *
 * Winsock2 already provides the same socket address structures and byte-order
 * helpers that the POSIX header defines, so we only need to include the
 * appropriate Windows headers.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* Vista / Server 2008 for inet_pton, etc. */
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

/* Ensure standard byte-order conversion macros exist under their POSIX names */
#ifndef htons
#define htons(x) _byteswap_ushort((x))
#endif
#ifndef htonl
#define htonl(x) _byteswap_ulong((x))
#endif
#ifndef ntohs
#define ntohs(x) _byteswap_ushort((x))
#endif
#ifndef ntohl
#define ntohl(x) _byteswap_ulong((x))
#endif

#else /* Non-Windows systems */

#include_next <netinet/in.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_NETINET_IN_H */