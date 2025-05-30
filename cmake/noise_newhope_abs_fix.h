#ifndef NOISE_NEWHOPE_ABS_FIX_H
#define NOISE_NEWHOPE_ABS_FIX_H

/* Included automatically for error_correction.c on MinGW to avoid the
   duplicate declaration of `abs` between <math.h> and the NewHope reference
   implementation.  
*/

#include <math.h>

#ifdef abs
#undef abs
#endif

#define abs newhope_internal_abs

#endif /* NOISE_NEWHOPE_ABS_FIX_H */