#ifndef PROTOCOL_TCP_UTIL_H
#define PROTOCOL_TCP_UTIL_H

#include <stdint.h>
#include <sys/socket.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>   
#include <stdbool.h>

#include "multiformats/multiaddr/multiaddr.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "transport/listener.h" 
#include "transport/transport.h"  

#ifdef __cplusplus
extern "C" {
#endif

/* ───────── SIGPIPE helpers ───────── */
void ignore_sigpipe_once(void);
int  sigpipe_block   (sigset_t *oldset);          /* returns 0 on success */
void sigpipe_restore (const sigset_t *oldset);

/* ───────── small helper utilities ───────── */
int      set_nonblocking   (int fd);
int      pct_encode_iface  (const char *iface,
                            char       *out,
                            size_t      out_len);
uint64_t now_mono_ms       (void);
void timespec_add_safe(struct timespec *ts,
                       int64_t         add_sec,
                       long            add_nsec);

/* ───────── address-classification helpers ───────── */
bool is_transport_code(uint64_t code);
bool tcp_can_handle  (const multiaddr_t *addr);

/* ───────── errno → transport-error helper ───────── */
libp2p_transport_err_t map_sockopt_errno(int errsv);

/* ───────── fatal-on-error mutex helpers ───────── */
int safe_mutex_lock  (pthread_mutex_t *mtx);
int safe_mutex_unlock(pthread_mutex_t *mtx);

/* ───────── lock-free helpers ───────── */
void     cas_backoff(_Atomic uint64_t *attempts);            /* may pass NULL */
unsigned listener_refcount_fetch_sub(libp2p_listener_t *l);  /* saturating */

/* ───────── multiaddr  ⇄  sockaddr helpers ───────── */
int           multiaddr_to_sockaddr(const multiaddr_t           *maddr,
                                    struct sockaddr_storage     *ss,
                                    socklen_t                   *ss_len);

multiaddr_t  *sockaddr_to_multiaddr(const struct sockaddr_storage *ss,
                                    socklen_t                      ss_len);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_TCP_UTIL_H */
