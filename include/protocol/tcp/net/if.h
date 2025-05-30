#ifndef LIBP2P_COMPAT_NET_IF_H
#define LIBP2P_COMPAT_NET_IF_H

/**
 * @file net/if.h
 * @brief Minimal stub of <net/if.h> for Windows builds.
 *
 * The current libp2p-c codebase only includes the header but does not
 * actually use any of its definitions when compiled for Windows,
 * therefore we provide just enough to satisfy the compiler.
 */

#ifdef _WIN32

/* POSIX requires IFNAMSIZ to be at least 16; define a sane default. */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* Windows has no concept of interface index names via POSIX APIs.  Provide
   no-op placeholders so that accidental usage still compiles. */

/** Translate an interface name to an index (always 0 on Windows). */
static inline unsigned if_nametoindex(const char *name)
{
    (void)name;
    return 0;
}

/** Translate an interface index to a name (always NULL on Windows). */
static inline char *if_indextoname(unsigned index, char *name)
{
    (void)index;
    (void)name;
    return NULL;
}

/** Return NULL as Windows lacks if_nameindex(). */
static inline char *if_nameindex(void) { return NULL; }

/** No-op free for if_nameindex() results. */
static inline void if_freenameindex(void *ptr) { (void)ptr; }

#else /* non-Windows */

/* On other platforms forward to the real header. */
#include_next <net/if.h>

#endif /* _WIN32 */

#endif /* LIBP2P_COMPAT_NET_IF_H */