#ifndef NOISE_FMUL_FIX_H
#define NOISE_FMUL_FIX_H

#include <math.h>

#ifdef fmul
#undef fmul
#endif
#define fmul fmul_donna

#endif /* NOISE_FMUL_FIX_H */
