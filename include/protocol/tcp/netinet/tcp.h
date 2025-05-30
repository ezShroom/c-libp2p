#ifndef LIBP2P_COMPAT_NETINET_TCP_H
#define LIBP2P_COMPAT_NETINET_TCP_H

/**
 * @file netinet/tcp.h
 * @brief Minimal <netinet/tcp.h> replacement for Windows.
 *
 * This header only exists so code can reference constants such as TCP_NODELAY
 * when compiled with MinGW or MSVC. Winsock already defines these constants in
 * <winsock2.h> / <ws2tcpip.h> so we merely include them and, if necessary,
 * forward-define the POSIX names.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

/* In the (unlikely) event that TCP_NODELAY is not yet defined via the above
   headers, provide a fallback definition that matches the standard value used
   by Winsock. */
#ifndef TCP_NODELAY
#define TCP_NODELAY 0x0001
#endif

#else /* non-Windows */

#include_next <netinet/tcp.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_NETINET_TCP_H */