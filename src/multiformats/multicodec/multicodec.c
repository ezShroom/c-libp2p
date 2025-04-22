#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multicodec/multicodec_table.h"

/**
 * @brief Look up the numeric code for a given codec name.
 *
 * @param name The name of the codec to look up. Must not be NULL.
 * @return The numeric code for the codec, or UINT64_MAX if the codec is not found.
 */
uint64_t multicodec_code_from_name(const char *name)
{
    if (!name)
    {
        return UINT64_MAX;
    }

    for (size_t i = 0; i < multicodec_table_len; ++i)
    {
        if (strcmp(name, multicodec_table[i].name) == 0)
        {
            return multicodec_table[i].code;
        }
    }

    return UINT64_MAX;
}

/**
 * @brief Look up the name of a given numeric code.
 *
 * @param code The numeric code to look up.
 * @return The name of the codec, or NULL if the code is not found.
 */
const char *multicodec_name_from_code(uint64_t code)
{
    for (size_t i = 0; i < multicodec_table_len; ++i)
    {
        if (code == multicodec_table[i].code)
        {
            return multicodec_table[i].name;
        }
    }

    return NULL;
}