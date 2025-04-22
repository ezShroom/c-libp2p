#ifndef MULTICODEC_H
#define MULTICODEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief A struct that maps a codec name to its numeric multicodec code.
 */
typedef struct
{
    const char *name;
    uint64_t code;
} multicodec_map_t;

/**
 * @brief Look up the numerical code for a given codec name.
 *
 * @param[in] name A null-terminated string (e.g. "identity", "ip4").
 * @return The matching numeric code (e.g. 0x00 for "identity"), or UINT64_MAX if not found.
 */
uint64_t multicodec_code_from_name(const char *name);

/**
 * @brief Look up the canonical string name for a given numeric code.
 *
 * @param[in] code The numeric multicodec code.
 * @return A pointer to the static string name (e.g. "identity"), or `NULL` if not found.
 */
const char *multicodec_name_from_code(uint64_t code);

#ifdef __cplusplus
}
#endif

#endif /* MULTICODEC_H */