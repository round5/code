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

#ifndef _MATMUL_H_
#define _MATMUL_H_

#include "r5_parameter_sets.h"

#if PARAMS_K != 1

// create a sparse ternary vector from a seed
void create_secret_vector_idx_s(uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2], const uint8_t *seed, const size_t seed_size);

void create_secret_vector_idx_r(uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2], const uint8_t *seed, const size_t seed_size);

#if PARAMS_TAU == 0
void matmul_as_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_N_BAR], modq_t a[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_D], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]);
void matmul_ra_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR], modq_t a[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_D], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]);
#elif PARAMS_TAU == 1
void matmul_as_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_N_BAR], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]);
void matmul_ra_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]);
#else
void matmul_as_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_N_BAR], modq_t a[PARAMS_Q + PARAMS_D], uint16_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]);
void matmul_ra_q(modq_t d[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR], modq_t a[PARAMS_Q + PARAMS_D], uint16_t a_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]);
#endif

void matmul_us_p(modp_t d[PARAMS_MU], modp_t u[PARAMS_D][PARAMS_M_BAR], uint16_t idx[PARAMS_N_BAR][PARAMS_H / 2][2]);

void matmul_rb_p(modp_t d[PARAMS_MU], modp_t b[PARAMS_D][PARAMS_N_BAR], uint16_t idx[PARAMS_M_BAR][PARAMS_H / 2][2]);

#endif /* PARAMS_K != 1 */

#endif /* _MATMUL_H_ */
