#ifndef PROTOCOL_MULTISELECT_H
#define PROTOCOL_MULTISELECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "transport/connection.h" /* libp2p_conn_t */

#ifdef __cplusplus
extern "C"
{
#endif

/* ------------------------------------------------------------------------- */
/*  Constants                                                                */
/* ------------------------------------------------------------------------- */

/** Canonical protocol id (without trailing newline). */
#define LIBP2P_MULTISELECT_PROTO_ID "/multistream/1.0.0"

/* Special message tokens (no newline). */
#define LIBP2P_MULTISELECT_NA "na"
#define LIBP2P_MULTISELECT_LS "ls"

/* ------------------------------------------------------------------------- */
/*  Error codes                                                              */
/* ------------------------------------------------------------------------- */

typedef enum
{
    LIBP2P_MULTISELECT_OK = 0,
    LIBP2P_MULTISELECT_ERR_NULL_PTR = -1,
    LIBP2P_MULTISELECT_ERR_TIMEOUT = -2,
    LIBP2P_MULTISELECT_ERR_UNAVAIL = -3,
    LIBP2P_MULTISELECT_ERR_PROTO_MAL = -4,
    LIBP2P_MULTISELECT_ERR_IO = -5,
    LIBP2P_MULTISELECT_ERR_INTERNAL = -6
} libp2p_multiselect_err_t;

/* ------------------------------------------------------------------------- */
/*  Configuration                                                            */
/* ------------------------------------------------------------------------- */

typedef struct
{
    uint64_t handshake_timeout_ms; /**< 0 → no timeout. */
    bool enable_ls;                /**< Listener answers `ls` requests. */
} libp2p_multiselect_config_t;

/** Canonical defaults: no timeout, `ls` disabled. */
static inline libp2p_multiselect_config_t libp2p_multiselect_config_default(void)
{
    return (libp2p_multiselect_config_t){.handshake_timeout_ms = 0, .enable_ls = false};
}

/* ------------------------------------------------------------------------- */
/*  Public API (dial / listen helpers)                                       */
/* ------------------------------------------------------------------------- */

/**
 * @brief Dial-side protocol negotiation.
 *
 * Walks @p proposals in order until the remote echoes one of them or all are
 * rejected.  Sends the multistream header automatically.
 *
 * @param conn          Raw connection (not consumed).
 * @param proposals     NULL-terminated list of protocol ids (UTF-8, no ‘\n’).
 * @param timeout_ms    0 → no timeout for the whole handshake.
 * @param accepted_out  Pointer to the entry actually chosen (may be NULL).
 */
libp2p_multiselect_err_t libp2p_multiselect_dial(libp2p_conn_t *conn, const char *const proposals[], uint64_t timeout_ms, const char **accepted_out);

/**
 * @brief Listen-side protocol negotiation.
 *
 * Waits for the peer’s choice (or `ls`).  If `ls` is requested and allowed by
 * @p cfg, responds with the full list before waiting for the final choice.
 *
 * @param conn          Raw connection (not consumed).
 * @param supported     NULL-terminated array of supported protocol ids.
 * @param cfg           Optional config (NULL → defaults).
 * @param accepted_out  Pointer to the entry actually selected (may be NULL).
 */
libp2p_multiselect_err_t libp2p_multiselect_listen(libp2p_conn_t *conn, const char *const supported[], const libp2p_multiselect_config_t *cfg,
                                                   const char **accepted_out);

/* ------------------------------------------------------------------------- */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PROTOCOL_MULTISELECT_H */