/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef _RINGMUL_H_
#define _RINGMUL_H_

#include "r5_parameter_sets.h"

#if PARAMS_K == 1

// multiplication mod q, result length n
void ringmul_q(modq_t d[PARAMS_N], modq_t a[PARAMS_N], tern_secret idx);

// multiplication mod p, result length mu
void ringmul_p(modp_t d[PARAMS_MU], modp_t a[PARAMS_N], tern_secret idx);

#endif

#endif /* _RINGMUL_H_ */
