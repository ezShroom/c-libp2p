#include <stdint.h>

/* Stand-alone definition of the helper previously mapped from abs() in the
   NewHope reference code.  Placed in its own translation unit to avoid symbol
   collisions. */

int32_t newhope_internal_abs(int32_t v)
{
    int32_t mask = v >> 31;
    return (v ^ mask) - mask;
}