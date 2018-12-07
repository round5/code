/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Oscar Garcia-Morchon, Hayo Baan
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

// Fast matrix arithmetic (without cache attack countermeasures)

#include "matmul.h"

#include <string.h>

#if PARAMS_K != 1 && !defined(CM_CACHE)

#include "drbg.h"
#include "little_endian.h"

// create a sparse ternary vector from a seed

void create_secret_vector_idx_s(uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2], const uint8_t *seed, const size_t seed_size) {
    size_t i, l;
    uint16_t x;
    uint8_t v[PARAMS_D];

    drbg_init(seed, seed_size);

    for (l = 0; l < PARAMS_N_BAR; l++) {
        memset(v, 0, sizeof (v));

        for (i = 0; i < PARAMS_H; i++) {
            do {
                do {
                    drbg(&x, sizeof (x));
                    x = (uint16_t) LITTLE_ENDIAN16(x);
                } while (x >= PARAMS_RS_LIM);
                x /= PARAMS_RS_DIV;
            } while (v[x]);
            v[x] = 1;
            idx[l][i >> 1][i & 1] = x; // addition / subtract index
        }
    }
}

// create a sparse ternary vector from a seed

void create_secret_vector_idx_r(uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2], const uint8_t *seed, const size_t seed_size) {
    size_t i, l;
    uint16_t x;
    uint8_t v[PARAMS_D];

    drbg_init(seed, seed_size);

    for (l = 0; l < PARAMS_M_BAR; l++) {
        memset(v, 0, sizeof (v));

        for (i = 0; i < PARAMS_H; i++) {
            do {
                do {
                    drbg(&x, sizeof (x));
                    x = (uint16_t) LITTLE_ENDIAN16(x);
                } while (x >= PARAMS_RS_LIM);
                x /= PARAMS_RS_DIV;
            } while (v[x]);
            v[x] = 1;
            idx[l][i >> 1][i & 1] = x; // addition / subtract index
        }
    }
}

// B = A * S

#if PARAMS_TAU == 0

void matmul_as_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_N_BAR], modq_t a[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_D], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]) {

#elif PARAMS_TAU == 1

void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]) {

#else

void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[PARAMS_Q + PARAMS_D], uint16_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]) {

#endif
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_N_BAR * PARAMS_D * sizeof (modq_t));

#if PARAMS_TAU == 0
#define A_element(x) a[j][idx[l][i][x]]
#else
#define A_element(x) a[a_permutation[j] + idx[l][i][x]]
#endif
    for (j = 0; j < PARAMS_D; j++) {
        for (l = 0; l < PARAMS_N_BAR; l++) {
            for (i = 0; i < PARAMS_H / 2; i++) {
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
            }
        }
    }
#undef A_element
}

// U = R * A

#if PARAMS_TAU == 0

void matmul_ra_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR], modq_t a[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_D], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]) {

#elif PARAMS_TAU == 1

void matmul_ra_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]) {

#else

void matmul_ra_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR], modq_t a[PARAMS_Q + PARAMS_D], uint16_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]) {

#endif
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_M_BAR * PARAMS_D * sizeof (modq_t));

#if PARAMS_TAU == 0
#define A_element(x) a[idx[l][i][x]][j]
#else
#define A_element(x) a[a_permutation[idx[l][i][x]] + j]
#endif
    for (l = 0; l < PARAMS_M_BAR; l++) {
        for (i = 0; i < PARAMS_H / 2; i++) {
            for (j = 0; j < PARAMS_D;) { // (partially) unrolled!
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#if (PARAMS_LOOP_UNROLL >= 1)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 2)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 3)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 4)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 5)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 6)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
#if (PARAMS_LOOP_UNROLL >= 7)
                d[j][l] = (modq_t) (d[j][l] + (A_element(0) - A_element(1)));
                j++;
#endif
            }
        }
    }
#undef A_element
}

#endif /* PARAMS_K != 1 && !defined(CM_CACHE) */

// X' = U * S
// Note: already always scan the same ranges, so no need to define cache attack version

void matmul_us_p(modp_t d[PARAMS_MU], modp_t u[PARAMS_D][PARAMS_M_BAR], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]) {
    size_t k, i, j;

    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));

    size_t index = 0;
    for (i = 0; i < PARAMS_N_BAR && index < PARAMS_MU; ++i) {
        for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; ++j) {
            for (k = 0; k < PARAMS_H / 2; ++k) {
                d[index] = (modp_t) (d[index] + (u[idx[i][k][0]][j] - u[idx[i][k][1]][j]));
            }
            ++index;
        }
    }
}

// X = R_T * B
// Note: already always scan the same ranges, so no need to define cache attack version

void matmul_rb_p(modp_t d[PARAMS_MU], modp_t b[PARAMS_D][PARAMS_N_BAR], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]) {
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));

    size_t index = 0;
    for (l = 0; l < PARAMS_N_BAR && index < PARAMS_MU; ++l) {
        for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; ++j) {
            for (i = 0; i < PARAMS_H / 2; ++i) {
                d[index] = (modp_t) (d[index] + (b[idx[j][i][0]][l] - b[idx[j][i][1]][l]));
            }
            ++index;
        }
    }
}
