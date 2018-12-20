/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Oscar Garcia-Morchon, Hayo Baan
 *
 * All rights reserved. A copyright license for redistribution and use in
 * source and binary forms, with or without modification, is hereby granted for
 * non-commercial, experimental, research, public review and evaluation
 * purposes, provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Fast ring arithmetic (without cache attack countermeasures)

#include "ringmul.h"
#include "r5_parameter_sets.h"

#if PARAMS_K == 1 && !defined(CM_CACHE)

#include "drbg.h"
#include "little_endian.h"

#include <string.h>

// create a sparse ternary vector from a seed

void create_secret_vector(uint16_t idx[PARAMS_H / 2][2], const uint8_t *seed, const size_t seed_size) {
    size_t i;
    uint16_t x;
    uint8_t v[PARAMS_ND];

    memset(v, 0, sizeof (v));
    drbg_init(seed, seed_size);

    for (i = 0; i < PARAMS_H; i++) {
        do {
            do {
                drbg(&x, sizeof (x));
                x = (uint16_t) LITTLE_ENDIAN16(x);
            } while (x >= PARAMS_RS_LIM);
            x /= PARAMS_RS_DIV;
        } while (v[x]);
        v[x] = 1;
        idx[i >> 1][i & 1] = x; // addition / subtract index
    }
}

// multiplication mod q, result length n

void ringmul_q(modq_t d[PARAMS_ND + PARAMS_LOOP_UNROLL], modq_t a[PARAMS_ND], uint16_t idx[PARAMS_H / 2][2]) {
    size_t i, j;
    modq_t *p_add, *p_sub;
    modq_t p[PARAMS_LOOP_UNROLL + 2 * (PARAMS_ND + 1)];

    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[PARAMS_LOOP_UNROLL + 0] = (modq_t) (-a[0]);
    for (i = 1; i < PARAMS_ND; i++) {
        p[PARAMS_LOOP_UNROLL + PARAMS_ND + 1 - i] = (modq_t) (a[i - 1] - a[i]);
    }
    p[PARAMS_LOOP_UNROLL + 1] = a[PARAMS_ND - 1];

    // Duplicate at the end
    memcpy(p + (PARAMS_LOOP_UNROLL + PARAMS_ND + 1), p + PARAMS_LOOP_UNROLL, (PARAMS_ND + 1) * sizeof (modq_t));

    // Initialize result
    memset(d, 0, PARAMS_ND * sizeof (modq_t));

    for (i = 0; i < PARAMS_H / 2; i++) {
        p_add = &p[PARAMS_LOOP_UNROLL + PARAMS_ND + 1 + idx[i][0]];
        p_sub = &p[PARAMS_LOOP_UNROLL + PARAMS_ND + 1 + idx[i][1]];

        for (j = 0; j < PARAMS_ND;) { // (partially) unrolled!
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#if (PARAMS_LOOP_UNROLL >= 1)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 2)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 3)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 4)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 5)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 6)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 7)
            d[j] = (modq_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
        }
    }

    // "unlift"
    d[0] = (uint16_t) (-d[0]);
    for (i = 1; i < PARAMS_ND; ++i) {
        d[i] = (uint16_t) (d[i - 1] - d[i]);
    }
}

// multiplication mod p, result length mu

void ringmul_p(modp_t d[PARAMS_MU + PARAMS_LOOP_UNROLL], modp_t a[PARAMS_ND], uint16_t idx[PARAMS_H / 2][2]) {
    size_t i, j;
    modp_t *p_add, *p_sub;
    modp_t p[PARAMS_LOOP_UNROLL + 2 * (PARAMS_ND + 1)];

    // Note: order of coefficients p[1..N] is reversed!
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[PARAMS_LOOP_UNROLL + 0] = (modp_t) (-a[0]);
    for (i = 1; i < PARAMS_ND; i++) {
        p[PARAMS_LOOP_UNROLL + PARAMS_ND + 1 - i] = (modp_t) (a[i - 1] - a[i]);
    }
    p[PARAMS_LOOP_UNROLL + 1] = a[PARAMS_ND - 1];
#else
    // With error correction we do not "lift"
    p[PARAMS_LOOP_UNROLL + 0] = a[0];
    for (i = 2; i < PARAMS_ND + 1; i++) {
        p[PARAMS_LOOP_UNROLL + i] = a[PARAMS_ND + 1 - i];
    }
    p[PARAMS_LOOP_UNROLL + 1] = 0;
#endif

    // Duplicate elements so we don't need to perform index modulo
    memcpy(p + (PARAMS_LOOP_UNROLL + PARAMS_ND + 1), p + PARAMS_LOOP_UNROLL, (PARAMS_ND + 1) * sizeof (modp_t));

    // Initialize result
    memset(d, 0, (PARAMS_MU + PARAMS_LOOP_UNROLL) * sizeof (modp_t));

    for (i = 0; i < PARAMS_H / 2; i++) {
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
        p_add = &p[PARAMS_LOOP_UNROLL + PARAMS_ND + 1 + idx[i][0]];
        p_sub = &p[PARAMS_LOOP_UNROLL + PARAMS_ND + 1 + idx[i][1]];
#else
        p_add = &p[PARAMS_LOOP_UNROLL + PARAMS_ND + idx[i][0]];
        p_sub = &p[PARAMS_LOOP_UNROLL + PARAMS_ND + idx[i][1]];
#endif
        for (j = 0; j < PARAMS_MU;) { // (partially) unrolled!
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#if (PARAMS_LOOP_UNROLL >= 1)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 2)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 3)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 4)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 5)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 6)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 7)
            d[j] = (modp_t) (d[j] + p_add[-j] - p_sub[-j]);
            j++;
#endif
        }
    }

#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lifted" so we now need to "unlift"
    d[0] = (modp_t) (-d[0]);
    for (i = 1; i < PARAMS_MU; ++i) {
        d[i] = (modp_t) (d[i - 1] - d[i]);
    }
#endif
}

#endif /* PARAMS_K == 1 && !defined(CM_CACHE) */
