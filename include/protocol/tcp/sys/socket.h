#ifndef LIBP2P_COMPAT_SYS_SOCKET_H
#define LIBP2P_COMPAT_SYS_SOCKET_H
/**
 * @file sys/socket.h
 * @brief Minimal Windows compatibility for <sys/socket.h>.
 */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <fcntl.h>
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef USE_EPOLL
#undef USE_EPOLL
#endif
#ifdef USE_KQUEUE
#undef USE_KQUEUE
#endif

/* Map POSIX shutdown() how flags are named on Windows */
#ifndef SHUT_RD
#define SHUT_RD SD_RECEIVE
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

/* POSIX send() flag MSG_NOSIGNAL is unsupported on Windows; define as 0 so
   code that passes it compiles and has no effect. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* For consistency with POSIX APIs, define socklen_t if the platform headers
   didn't already. */
#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

/** @brief sigset_t / SIGPIPE helpers */
#ifndef HAVE_SIGSET_T
typedef unsigned long sigset_t;
#define HAVE_SIGSET_T 1
#endif

/** Block SIGPIPE on Windows (no-op).
 *  @param oldset Unused.
 *  @return Always 0. */
static inline int sigpipe_block(sigset_t *oldset)
{
    (void)oldset;
    return 0;
}

/** Restore SIGPIPE mask (no-op). */
static inline void sigpipe_restore(const sigset_t *oldset) { (void)oldset; }

/** Ignore SIGPIPE for a single send (no-op). */
static inline void ignore_sigpipe_once(void) { /* nothing on Windows */ }

/** @brief pipe() compatibility */
#ifndef LIBP2P_HAVE_PIPE_WRAP
#define LIBP2P_HAVE_PIPE_WRAP 1
/** Create a pipe using the Windows _pipe API. */
static inline int pipe(int fds[2])
{
    /* 4 KiB default buffer, binary mode */
    return _pipe(fds, 4096, _O_BINARY);
}
#endif

/** @brief fcntl() compatibility */
#ifndef F_GETFL
#define F_GETFL 0
#endif
#ifndef F_SETFL
#define F_SETFL 1
#endif
#ifndef F_GETFD
#define F_GETFD 2
#endif
#ifndef F_SETFD
#define F_SETFD 3
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x0004
#endif
#ifndef FD_CLOEXEC
#define FD_CLOEXEC 0
#endif

#include <stdarg.h>
/** Very small fcntl stub returning success. */
static inline int fcntl(int fd, int cmd, ...)
{
    (void)fd;
    (void)cmd;
    /* No-op stub: always succeed, pretend unchanged */
    return 0;
}

#else /* non-Windows */

#include_next <sys/socket.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_SYS_SOCKET_H */