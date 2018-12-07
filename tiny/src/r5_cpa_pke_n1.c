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

#include "r5_cpa_pke.h"
#include "parameters.h"

#if PARAMS_K != 1

#include "api.h"
#include "r5_hash.h"
#include "rng.h"
#include "xef.h"
#include "matmul.h"
#include "misc.h"
#include "a_random.h"

#include <stdio.h>
#include <string.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

/* Wrapper around xef functions so we can seamlessly make use of the optimized xe5 */
#if PARAMS_F == 5
#if PARAMS_XE == 190
#define XEF(function, block, len, f) xe5_190_##function(block)
#elif PARAMS_XE == 218
#define XEF(function, block, len, f) xe5_218_##function(block)
#elif PARAMS_XE == 234
#define XEF(function, block, len, f) xe5_234_##function(block)
#endif
#else
#define XEF(function, block, len, f) xef_##function(block, len, f)
#endif
#define xef_compute(block, len, f) XEF(compute, block, len, f)
#define xef_fixerr(block, len, f) XEF(fixerr, block, len, f)

#endif

#if PARAMS_TAU != 0
#include "little_endian.h"
#include "drbg.h"

/**
 * The DRBG customization when creating the tau=1 or tau=2 permutations.
 */
static const uint8_t permutation_customization[2] = {0, 1};
#endif

#if PARAMS_TAU == 1

#include "a_fixed.h"

static int create_A_permutation(uint32_t A_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], const unsigned char *sigma) {
    /* Compute the permutation */
    uint16_t x;
    drbg_init_customization(sigma, PARAMS_KAPPA_BYTES, permutation_customization, sizeof (permutation_customization));
    for (uint32_t i = 0; i < PARAMS_D; ++i) {
        do {
            drbg(&x, sizeof (x));
            x = (uint16_t) LITTLE_ENDIAN16(x);
        } while (x >= PARAMS_RS_LIM);
        x = (uint16_t) (x / PARAMS_RS_DIV);
        A_permutation[i] = 2 * i * PARAMS_D + x;
    }
#if PARAMS_LOOP_UNROLL > 0
    for (uint32_t i = PARAMS_D; i < PARAMS_D + PARAMS_LOOP_UNROLL; ++i) {
        A_permutation[i] = 0;
    }
#endif

    return 0;
}

#elif PARAMS_TAU == 2

static int create_A_permutation(uint16_t A_permutation[PARAMS_D + PARAMS_LOOP_UNROLL], const unsigned char *sigma) {
    /* Compute the permutation */
    uint16_t x;
    drbg_init_customization(sigma, PARAMS_KAPPA_BYTES, permutation_customization, sizeof (permutation_customization));
    for (uint32_t i = 0; i < PARAMS_D; ++i) {
        drbg(&x, sizeof (x));
        A_permutation[i] = (uint16_t) (LITTLE_ENDIAN16(x) & (PARAMS_Q - 1));
    }
#if PARAMS_LOOP_UNROLL > 0
    for (uint32_t i = PARAMS_D; i < PARAMS_D + PARAMS_LOOP_UNROLL; ++i) {
        A_permutation[i] = 0;
    }
#endif

    return 0;
}

#endif

// compress D*M_BAR elements of q bits into p bits and pack into a byte string

static void pack_q_p_m_bar(uint8_t *pv, const modq_t *vq, const modq_t rounding_constant) {
#if (PARAMS_P_BITS == 8)
    size_t i;

    for (i = 0; i < PARAMS_D * PARAMS_M_BAR; ++i) {
        pv[i * PARAMS_M_BAR] = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
    }
#else
    size_t i, j;
    modp_t t;

    memset(pv, 0, (size_t) BITS_TO_BYTES(PARAMS_P_BITS * PARAMS_D * PARAMS_M_BAR));
    j = 0;
    for (i = 0; i < PARAMS_D * PARAMS_M_BAR; ++i) {
        t = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
        //pack p bits
        pv[j >> 3] |= (uint8_t) (t << (j & 7));
        if ((j & 7) + PARAMS_P_BITS > 8) {
            pv[(j >> 3) + 1] |= (uint8_t) (t >> (8 - (j & 7)));
            if ((j & 7) + PARAMS_P_BITS > 16) {
                pv[(j >> 3) + 2] |= (uint8_t) (t >> (16 - (j & 7)));
            }
        }
        j += PARAMS_P_BITS;
    }
#endif
}

// compress D*N_BAR elements of q bits into p bits and pack into a byte string

static void pack_q_p_n_bar(uint8_t *pv, const modq_t *vq, const modq_t rounding_constant) {
#if (PARAMS_P_BITS == 8)
    size_t i;

    for (i = 0; i < PARAMS_D * PARAMS_N_BAR; ++i) {
        pv[i * PARAMS_N_BAR] = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
    }
#else
    size_t i, j;
    modp_t t;

    memset(pv, 0, (size_t) BITS_TO_BYTES(PARAMS_P_BITS * PARAMS_D * PARAMS_N_BAR));
    j = 0;
    for (i = 0; i < PARAMS_D * PARAMS_N_BAR; ++i) {
        t = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
        //pack p bits
        pv[j >> 3] |= (uint8_t) (t << (j & 7));
        if ((j & 7) + PARAMS_P_BITS > 8) {
            pv[(j >> 3) + 1] |= (uint8_t) (t >> (8 - (j & 7)));
            if ((j & 7) + PARAMS_P_BITS > 16) {
                pv[(j >> 3) + 2] |= (uint8_t) (t >> (16 - (j & 7)));
            }
        }
        j += PARAMS_P_BITS;
    }
#endif
}

// unpack a byte string into D*M_BAR elements of p bits

static void unpack_p_m_bar(modp_t *vp, const uint8_t *pv) {
#if (PARAMS_P_BITS == 8)
    memcpy(vp, pv, PARAMS_D * PARAMS_M_BAR);
#else
    size_t i, bits_done, idx, bit_idx;
    modp_t val;

    bits_done = 0;
    for (i = 0; i < PARAMS_D * PARAMS_M_BAR; i++) {
        idx = bits_done >> 3;
        bit_idx = bits_done & 7;
        val = (uint16_t) (pv[idx] >> bit_idx);
        if (bit_idx + PARAMS_P_BITS > 8) {
            /* Get spill over from next packed byte */
            val = (uint16_t) (val | (pv[idx + 1] << (8 - bit_idx)));
            if (bit_idx + PARAMS_P_BITS > 16) {
                /* Get spill over from next packed byte */
                val = (uint16_t) (val | (pv[idx + 2] << (16 - bit_idx)));
            }
        }
        vp[i] = val & (PARAMS_P - 1);
        bits_done += PARAMS_P_BITS;
    }
#endif
}

// unpack a byte string into D*N_BAR elements of p bits

static void unpack_p_n_bar(modp_t *vp, const uint8_t *pv) {
#if (PARAMS_P_BITS == 8)
    memcpy(vp, pv, PARAMS_D * PARAMS_N_BAR);
#else
    size_t i, bits_done, idx, bit_idx;
    modp_t val;

    bits_done = 0;
    for (i = 0; i < PARAMS_D * PARAMS_N_BAR; i++) {
        idx = bits_done >> 3;
        bit_idx = bits_done & 7;
        val = (uint16_t) (pv[idx] >> bit_idx);
        if (bit_idx + PARAMS_P_BITS > 8) {
            /* Get spill over from next packed byte */
            val = (uint16_t) (val | (pv[idx + 1] << (8 - bit_idx)));
            if (bit_idx + PARAMS_P_BITS > 16) {
                /* Get spill over from next packed byte */
                val = (uint16_t) (val | (pv[idx + 2] << (16 - bit_idx)));
            }
        }
        vp[i] = val & (PARAMS_P - 1);
        bits_done += PARAMS_P_BITS;
    }
#endif
}

// generate a keypair (sigma, B)

int r5_cpa_pke_keygen(uint8_t *pk, uint8_t *sk) {
    modq_t B[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_N_BAR];
    uint16_t S_idx[PARAMS_N_BAR][PARAMS_H / 2][2];

    randombytes(pk, PARAMS_KAPPA_BYTES); // sigma = seed of (permutation of) A
#if defined(ROUND5_INTERMEDIATE) || defined(DEBUG)
    printf("r5_cpa_pke_keygen: tau=%u\n", PARAMS_TAU);
    print_hex("r5_cpa_pke_keygen: sigma", pk, PARAMS_KAPPA_BYTES, 1);
#endif


#if PARAMS_TAU == 0
    modq_t A_random[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_D];
    // A from sigma
    create_A_random((modq_t *) A_random, pk);
#define A_matrix A_random
#define A_element(r,c) A_random[r][c]
#elif PARAMS_TAU == 1
    uint32_t A_permutation[PARAMS_D + PARAMS_LOOP_UNROLL];
    // Permutation of A_fixed
    create_A_permutation(A_permutation, pk);
#define A_matrix A_fixed
#define A_element(r,c) A_fixed[A_permutation[r] + (uint32_t) c]
#elif PARAMS_TAU == 2
    modq_t A_random[PARAMS_Q + PARAMS_D];
    // A from sigma
    create_A_random(A_random, pk);
    memcpy(A_random + PARAMS_Q, A_random, PARAMS_D * sizeof (modq_t));
    uint16_t A_permutation[PARAMS_D + PARAMS_LOOP_UNROLL];
    // Permutation of A_random
    create_A_permutation(A_permutation, pk);
#define A_matrix A_random
#define A_element(r,c) A_random[A_permutation[r] + (uint32_t) c]
#endif

    randombytes(sk, PARAMS_KAPPA_BYTES); // secret key -- Random S
    create_secret_vector_idx_s(S_idx, sk, PARAMS_KAPPA_BYTES);
#ifdef DEBUG
    modq_t DEBUG_OUT_A[PARAMS_D][PARAMS_D];
    for (int i = 0; i < PARAMS_D; ++i) {
        for (int j = 0; j < PARAMS_D; ++j) {
            DEBUG_OUT_A[i][j] = (uint16_t) (A_element(i, j) & (PARAMS_Q - 1));
        }
    }
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: A", &DEBUG_OUT_A[0][0], PARAMS_K, PARAMS_K, PARAMS_N);
#endif
#if PARAMS_TAU == 0
    matmul_as_q(B, A_matrix, S_idx); // B = A * S
#else
    matmul_as_q(B, A_matrix, A_permutation, S_idx); // B = A * S
#endif
#ifdef DEBUG
    for (int i = 0; i < PARAMS_D; ++i) {
        for (int j = 0; j < PARAMS_N_BAR; ++j) {
            B[i][j] = (uint16_t) (B[i][j] & (PARAMS_Q - 1));
        }
    }
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: uncompressed B", &B[0][0], PARAMS_K, PARAMS_N_BAR, PARAMS_N);

    int16_t S_T[PARAMS_N_BAR][PARAMS_D] = {
        {0}
    };
    for (int i = 0; i < PARAMS_N_BAR; ++i) {
        for (int j = 0; j < PARAMS_H / 2; ++j) {
            S_T[i][S_idx[i][j][0]] = 1;
            S_T[i][S_idx[i][j][1]] = -1;
        }
    }
    print_sage_s_vector_matrix("r5_cpa_pke_keygen: S_T", &S_T[0][0], PARAMS_N_BAR, PARAMS_K, PARAMS_N);
#endif

    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p_n_bar(pk + PARAMS_KAPPA_BYTES, &B[0][0], PARAMS_H1);
    return 0;
}

int r5_cpa_pke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t *m, const uint8_t *rho) {
    size_t i, j;
    uint16_t R_idx[PARAMS_M_BAR][PARAMS_H / 2][2];
    modq_t U[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_M_BAR];
    modp_t B[PARAMS_D][PARAMS_N_BAR];
    modp_t X[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];
    modp_t t, tm;

    // unpack public key
    unpack_p_n_bar(&B[0][0], pk + PARAMS_KAPPA_BYTES);

#undef A_matrix
#undef A_element
#if PARAMS_TAU == 0
    modq_t A_random[PARAMS_D + PARAMS_LOOP_UNROLL][PARAMS_K];
    // A from sigma
    create_A_random((modq_t *) A_random, pk);
#define A_matrix A_random
#define A_element(r,c) A_random[r][c]
#elif PARAMS_TAU == 1
    uint32_t A_permutation[PARAMS_D + PARAMS_LOOP_UNROLL];
    // Permutation of A_fixed
    create_A_permutation(A_permutation, pk);
#define A_matrix A_fixed
#define A_element(r,c) A_fixed[A_permutation[r] + (uint32_t) c]
#elif PARAMS_TAU == 2
    modq_t A_random[PARAMS_Q + PARAMS_D];
    // A from sigma
    create_A_random(A_random, pk);
    memcpy(A_random + PARAMS_Q, A_random, PARAMS_D * sizeof (modq_t));
    uint16_t A_permutation[PARAMS_D + PARAMS_LOOP_UNROLL];
    // Permutation of A_random
    create_A_permutation(A_permutation, pk);
#define A_matrix A_random
#define A_element(r,c) A_random[A_permutation[r] + (uint32_t) c]
#endif

    memcpy(m1, m, PARAMS_KAPPA_BYTES);
    memset(m1 + PARAMS_KAPPA_BYTES, 0, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS) - PARAMS_KAPPA_BYTES);
#if (PARAMS_XE != 0)
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif

    // Create R
    create_secret_vector_idx_r(R_idx, rho, PARAMS_KAPPA_BYTES);

#if PARAMS_TAU == 0
    matmul_ra_q(U, A_matrix, R_idx); // U = R^t x A   (mod q)
#else
    matmul_ra_q(U, A_matrix, A_permutation, R_idx); // U = R^t x A   (mod q)
#endif
    matmul_rb_p(X, B, R_idx); // X = R^t x B   (mod p)

#if defined(ROUND5_INTERMEDIATE) || defined(DEBUG)
#ifdef DEBUG
    print_hex("encrypt_rho: m", m, PARAMS_KAPPA_BYTES, 1);
#endif
    print_hex("encrypt_rho: rho", rho, PARAMS_KAPPA_BYTES, 1);
    print_hex("encrypt_rho: sigma", pk, PARAMS_KAPPA_BYTES, 1);
#ifdef DEBUG
    modq_t DEBUG_OUT_A[PARAMS_D][PARAMS_D];
    for (int i = 0; i < PARAMS_D; ++i) {
        for (int j = 0; j < PARAMS_D; ++j) {
            DEBUG_OUT_A[i][j] = (uint16_t) (A_element(i, j) & (PARAMS_Q - 1));
        }
    }
    print_sage_u_vector_matrix("encrypt_rho: A", &DEBUG_OUT_A[0][0], PARAMS_K, PARAMS_K, PARAMS_N);
    print_sage_u_vector_matrix("encrypt_rho: B", &B[0][0], PARAMS_K, PARAMS_N_BAR, PARAMS_N);

    int16_t R_T[PARAMS_M_BAR][PARAMS_D] = {
        {0}
    };
    for (i = 0; i < PARAMS_M_BAR; ++i) {
        for (j = 0; j < PARAMS_H / 2; ++j) {
            R_T[i][R_idx[i][j][0]] = 1;
            R_T[i][R_idx[i][j][1]] = -1;
        }
    }
    print_sage_s_vector_matrix("encrypt_rho: R_T", &R_T[0][0], PARAMS_K, PARAMS_M_BAR, PARAMS_N);
    uint16_t DEBUG_OUT_U[PARAMS_D][PARAMS_M_BAR];
    for (i = 0; i < PARAMS_D; ++i) {
        for (j = 0; j < PARAMS_M_BAR; ++j) {
            DEBUG_OUT_U[i][j] = (uint16_t) (U[i][j] & (PARAMS_Q - 1));
        }
    }
    print_sage_u_vector_matrix("encrypt_rho: uncompressed U", &DEBUG_OUT_U[0][0], PARAMS_K, PARAMS_M_BAR, PARAMS_N);

    uint16_t DEBUG_OUT_X[PARAMS_MU];
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT_X[i] = (uint16_t) (X[i] & (PARAMS_P - 1));
    }
    print_sage_u_vector("encrypt_rho: uncompressed X", DEBUG_OUT_X, PARAMS_MU);
#endif
    print_hex("encrypt_rho: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
#endif

    pack_q_p_m_bar(ct, &U[0][0], PARAMS_H2); // ct = U | v

    memset(ct + PARAMS_DPU_SIZE, 0, PARAMS_MUT_SIZE);
    j = 8 * PARAMS_DPU_SIZE;

    for (i = 0; i < PARAMS_MU; i++) { // compute, pack v
        // compress p->t
        t = (modp_t) ((X[i] + PARAMS_H2) >> (PARAMS_P_BITS - PARAMS_T_BITS));
        // add message
        tm = (modp_t) (m1[(i * PARAMS_B_BITS) >> 3] >> ((i * PARAMS_B_BITS) & 7));
#if (8 % PARAMS_B_BITS != 0)
        if (((i * PARAMS_B_BITS) & 7) + PARAMS_B_BITS > 8) {
            /* Get spill over from next message byte */
            tm = (modp_t) (tm | (m1[((i * PARAMS_B_BITS) >> 3) + 1] << (8 - ((i * PARAMS_B_BITS) & 7))));
        }
#endif
        t = (modp_t) (t + ((tm & ((1 << PARAMS_B_BITS) - 1)) << (PARAMS_T_BITS - PARAMS_B_BITS))) & ((1 << PARAMS_T_BITS) - 1);

        ct[j >> 3] |= (uint8_t) (t << (j & 7)); // pack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            ct[(j >> 3) + 1] |= (uint8_t) (t >> (8 - (j & 7)));
            if ((j & 7) + PARAMS_T_BITS > 16) {
                ct[(j >> 3) + 2] |= (uint8_t) (t >> (16 - (j & 7)));
            }
        }
        j += PARAMS_T_BITS;
    }

    return 0;
}

int r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
    size_t i, j;
    uint16_t S_idx[PARAMS_N_BAR][PARAMS_H / 2][2];
    modp_t U[PARAMS_D][PARAMS_M_BAR];
    modp_t v[PARAMS_MU];
    modp_t t, X_prime[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];

    create_secret_vector_idx_s(S_idx, sk, PARAMS_KAPPA_BYTES);

    unpack_p_m_bar((modp_t *) U, ct); // ct = U | v

    j = 8 * PARAMS_DPU_SIZE;
    for (i = 0; i < PARAMS_MU; i++) {
        t = (modp_t) (ct[j >> 3] >> (j & 7)); // unpack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            t |= (modp_t) (ct[(j >> 3) + 1] << (8 - (j & 7)));
            if ((j & 7) + PARAMS_T_BITS > 16) {
                t |= (modp_t) ((ct[(j >> 3) + 2]) << (16 - (j & 7)));
            }
        }
        v[i] = t & ((1 << PARAMS_T_BITS) - 1);
        j += PARAMS_T_BITS;
    }

#ifdef DEBUG
    uint16_t DEBUG_OUT_U[PARAMS_D][PARAMS_M_BAR];
    for (i = 0; i < PARAMS_D; ++i) {
        for (j = 0; j < PARAMS_M_BAR; ++j) {
            DEBUG_OUT_U[i][j] = U[i][j] & (PARAMS_P - 1);
        }
    }
    print_sage_u_vector_matrix("r5_cpa_pke_decrypt: compressed U", &DEBUG_OUT_U[0][0], PARAMS_K, PARAMS_M_BAR, PARAMS_N);
    uint16_t DEBUG_OUT_v[PARAMS_MU];
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT_v[i] = v[i];
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: compressed v", DEBUG_OUT_v, PARAMS_MU);
#endif

    // X' = U * S (mod p)
    matmul_us_p(X_prime, U, S_idx);

#ifdef DEBUG
    uint16_t DEBUG_OUT_x[PARAMS_MU];
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT_x[i] = (uint16_t) X_prime[i] & (PARAMS_P - 1);
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: X'", DEBUG_OUT_x, PARAMS_MU);
#endif

    // X' = v - X', compressed to 1 bit
    modp_t x_p;
    memset(m1, 0, sizeof (m1));
    for (i = 0; i < PARAMS_MU; i++) {
        // v - X' as mod q value (to be able to perform the rounding!)
        x_p = (modp_t) ((v[i] << (PARAMS_P_BITS - PARAMS_T_BITS)) - X_prime[i]);
#ifdef DEBUG
        DEBUG_OUT_x[i] = x_p & (PARAMS_P - 1);
#endif
        x_p = (modp_t) (((x_p + PARAMS_H3) >> (PARAMS_P_BITS - PARAMS_B_BITS)) & ((1 << PARAMS_B_BITS) - 1));
#ifdef DEBUG
        X_prime[i] = x_p;
#endif
        m1[i * PARAMS_B_BITS >> 3] = (uint8_t) (m1[i * PARAMS_B_BITS >> 3] | (x_p << ((i * PARAMS_B_BITS) & 7)));
#if (8 % PARAMS_B_BITS != 0)
        if (((i * PARAMS_B_BITS) & 7) + PARAMS_B_BITS > 8) {
            /* Spill over to next message byte */
            m1[(i * PARAMS_B_BITS >> 3) + 1] = (uint8_t) (m1[(i * PARAMS_B_BITS >> 3) + 1] | (x_p >> (8 - ((i * PARAMS_B_BITS) & 7))));
        }
#endif
    }

#ifdef DEBUG
    print_sage_u_vector("r5_cpa_pke_decrypt: uncompressed m2", DEBUG_OUT_x, PARAMS_MU);
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT_x[i] = X_prime[i];
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: m2", DEBUG_OUT_x, PARAMS_MU);
    print_hex("r5_cpa_pke_decrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
#endif

#if (PARAMS_XE != 0)
    // Apply error correction
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
    xef_fixerr(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif
    memcpy(m, m1, PARAMS_KAPPA_BYTES);

#if defined(ROUND5_INTERMEDIATE) || defined(DEBUG)
    print_hex("r5_cpa_pke_decrypt: m", m, PARAMS_KAPPA_BYTES, 1);
#endif

    return 0;
}

#endif /* PARAMS_K != 1 */
