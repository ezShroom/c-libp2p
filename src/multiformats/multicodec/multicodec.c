#include <string.h>

#include "multiformats/multicodec/multicodec.h"
#include "multiformats/multicodec/multicodec_codes.h"
#include "multiformats/multicodec/multicodec_mappings.h"

/**
 * @brief The number of mappings in the multicodec_mappings array.
 *
 * Assumes that multicodec_mappings is a statically defined array.
 */
static const int NUM_MAPPINGS = sizeof(multicodec_mappings) / sizeof(multicodec_mappings[0]);

/**
 * @brief Look up the numeric code for a given codec name.
 *
 * @param name The name of the codec to look up. Must not be NULL.
 * @return The numeric code for the codec, or 0 if the codec is not found.
 *         Note: 0 is reserved as the "not found" indicator.
 */
uint64_t multicodec_code_from_name(const char *name)
{
    if (name == NULL)
    {
        return 0;
    }

    for (int i = 0; i < NUM_MAPPINGS; i++)
    {
        if (strcmp(name, multicodec_mappings[i].name) == 0)
        {
            return multicodec_mappings[i].code;
        }
    }
    return 0;
}

/**
 * @brief Look up the name of a given numeric code.
 *
 * @param code The numeric code to look up.
 * @return The name of the codec, or NULL if the code is not found.
 */
const char *multicodec_name_from_code(uint64_t code)
{
    for (int i = 0; i < NUM_MAPPINGS; i++)
    {
        if (code == multicodec_mappings[i].code)
        {
            return multicodec_mappings[i].name;
        }
    }
    return NULL;
}