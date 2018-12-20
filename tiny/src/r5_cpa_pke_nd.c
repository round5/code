/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Hayo Baan
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
#include "r5_parameter_sets.h"

#if PARAMS_K == 1

#include "r5_hash.h"
#include "rng.h"
#include "xef.h"
#include "ringmul.h"
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

// compress ND elements of q bits into p bits and pack into a byte string

static void pack_q_p(uint8_t *pv, const modq_t *vq, const modq_t rounding_constant) {
#if (PARAMS_P_BITS == 8)
    size_t i;

    for (i = 0; i < PARAMS_ND; i++) {
        pv[i] = (uint8_t) (((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1));
    }
#else
    size_t i, j;
    modp_t t;

    memset(pv, 0, PARAMS_NDP_SIZE);
    j = 0;
    for (i = 0; i < PARAMS_ND; i++) {
        t = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
        pv[j >> 3] = (uint8_t) (pv[j >> 3] | (t << (j & 7))); // pack p bits
        if ((j & 7) + PARAMS_P_BITS > 8) {
            pv[(j >> 3) + 1] = (uint8_t) (pv[(j >> 3) + 1] | (t >> (8 - (j & 7))));
        }
        j += PARAMS_P_BITS;
    }
#endif
}

// unpack a byte string into ND elements of p bits

static void unpack_p(modp_t *vp, const uint8_t *pv) {
#if (PARAMS_P_BITS == 8)
    memcpy(vp, pv, PARAMS_ND);
#else
    size_t i, j;
    modp_t t;

    j = 0;
    for (i = 0; i < PARAMS_ND; i++) {
        t = (modp_t) (pv[j >> 3] >> (j & 7)); // unpack p bits
        if ((j & 7) + PARAMS_P_BITS > 8) {
            t = (modp_t) (t | ((modp_t) pv[(j >> 3) + 1]) << (8 - (j & 7)));
        }
        vp[i] = t & (PARAMS_P - 1);
        j += PARAMS_P_BITS;
    }
#endif
}

// generate a keypair (sigma, B)

int r5_cpa_pke_keygen(uint8_t *pk, uint8_t *sk) {
    modq_t A[PARAMS_ND];
    modq_t B[PARAMS_ND + PARAMS_LOOP_UNROLL];
    uint16_t S_idx[PARAMS_H / 2][2];

    randombytes(pk, PARAMS_KAPPA_BYTES); // sigma = seed of A
#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    printf("r5_cpa_pke_keygen: tau=%u\n", PARAMS_TAU);
    print_hex("r5_cpa_pke_keygen: sigma", pk, PARAMS_KAPPA_BYTES, 1);
#endif

    // A from sigma
    create_A_random(A, pk);

    randombytes(sk, PARAMS_KAPPA_BYTES); // secret key -- Random S
    create_secret_vector(S_idx, sk, PARAMS_KAPPA_BYTES);
#ifdef DEBUG
    for (int i = 0; i < PARAMS_ND; ++i) {
        A[i] = (uint16_t) (A[i] & (PARAMS_Q - 1));
    }
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: A", A, PARAMS_K, PARAMS_K, PARAMS_N);
#endif

    ringmul_q(B, A, S_idx); // B = A * S
#ifdef DEBUG
    for (int i = 0; i < PARAMS_ND; ++i) {
        B[i] = (uint16_t) (B[i] & (PARAMS_Q - 1));
    }
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: uncompressed B", B, PARAMS_K, PARAMS_N_BAR, PARAMS_N);

    int16_t S_T[PARAMS_ND] = {0};
    for (int i = 0; i < PARAMS_H / 2; ++i) {
        S_T[S_idx[i][0]] = 1;
        S_T[S_idx[i][1]] = -1;
    }
    print_sage_s_vector_matrix("r5_cpa_pke_keygen: S_T", S_T, PARAMS_N_BAR, PARAMS_K, PARAMS_N);
#endif

    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_q_p(pk + PARAMS_KAPPA_BYTES, B, PARAMS_H1);

    return 0;
}

int r5_cpa_pke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t *m, const uint8_t *rho) {
    size_t i, j;
    modq_t A[PARAMS_ND];
    uint16_t R_idx[PARAMS_H / 2][2];
    modq_t U[PARAMS_ND + PARAMS_LOOP_UNROLL];
    modp_t B[PARAMS_ND];
    modp_t X[PARAMS_MU + PARAMS_LOOP_UNROLL];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];
    modp_t t, tm;

    // unpack public key
    unpack_p(B, pk + PARAMS_KAPPA_BYTES);

    // A from sigma
    create_A_random(A, pk);

    memcpy(m1, m, PARAMS_KAPPA_BYTES); // add error correction code
    memset(m1 + PARAMS_KAPPA_BYTES, 0, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS) - PARAMS_KAPPA_BYTES);
#if (PARAMS_XE != 0)
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif

    // Create R
    create_secret_vector(R_idx, rho, PARAMS_KAPPA_BYTES);

    ringmul_q(U, A, R_idx); // U = A * R  (mod q)
    ringmul_p(X, B, R_idx); // X = B * R  (mod p)

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
#ifdef DEBUG
    print_hex("r5_cpa_pke_encrypt: m", m, PARAMS_KAPPA_BYTES, 1);
#endif
    print_hex("r5_cpa_pke_encrypt: rho", rho, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cpa_pke_encrypt: sigma", pk, PARAMS_KAPPA_BYTES, 1);
#ifdef DEBUG
    for (i = 0; i < PARAMS_ND; ++i) {
        A[i] &= (PARAMS_Q - 1);
    }
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: A", A, PARAMS_K, PARAMS_K, PARAMS_N);
    uint16_t DEBUG_OUT[PARAMS_ND];
    for (i = 0; i < PARAMS_ND; ++i) {
        DEBUG_OUT[i] = B[i];
    }
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: B", DEBUG_OUT, PARAMS_K, PARAMS_N_BAR, PARAMS_N);

    int16_t R_T[PARAMS_ND] = {0};
    for (i = 0; i < PARAMS_H / 2; ++i) {
        R_T[R_idx[i][0]] = 1;
        R_T[R_idx[i][1]] = -1;
    }
    print_sage_s_vector_matrix("r5_cpa_pke_encrypt: R_T", R_T, PARAMS_K, PARAMS_M_BAR, PARAMS_N);
    for (i = 0; i < PARAMS_ND; ++i) {
        DEBUG_OUT[i] = (uint16_t) (U[i] & (PARAMS_Q - 1));
    }
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: uncompressed U", DEBUG_OUT, PARAMS_K, PARAMS_M_BAR, PARAMS_N);

    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT[i] = (uint16_t) (X[i] & (PARAMS_P - 1));
    }
    print_sage_u_vector("r5_cpa_pke_encrypt: uncompressed X", DEBUG_OUT, PARAMS_MU);
#endif
    print_hex("r5_cpa_pke_encrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
#endif

    pack_q_p(ct, U, PARAMS_H2); // ct = U | v

    memset(ct + PARAMS_NDP_SIZE, 0, PARAMS_MUT_SIZE);
    j = 8 * PARAMS_NDP_SIZE;

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

        ct[j >> 3] = (uint8_t) (ct[j >> 3] | (t << (j & 7))); // pack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            ct[(j >> 3) + 1] = (uint8_t) (ct[(j >> 3) + 1] | (t >> (8 - (j & 7))));
        }
        j += PARAMS_T_BITS;
    }

    return 0;
}

int r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
    size_t i, j;
    uint16_t S_idx[PARAMS_H / 2][2];
    modp_t U[PARAMS_ND];
    modp_t v[PARAMS_MU];
    modp_t t, X_prime[PARAMS_MU + PARAMS_LOOP_UNROLL];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];

    create_secret_vector(S_idx, sk, PARAMS_KAPPA_BYTES);

    unpack_p(U, ct); // ct = U | v

    j = 8 * PARAMS_NDP_SIZE;
    for (i = 0; i < PARAMS_MU; i++) {
        t = (modp_t) (ct[j >> 3] >> (j & 7)); // unpack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            t = (modp_t) (t | ct[(j >> 3) + 1] << (8 - (j & 7)));
        }
        v[i] = t & ((1 << PARAMS_T_BITS) - 1);
        j += PARAMS_T_BITS;
    }

#ifdef DEBUG
    uint16_t DEBUG_OUT[PARAMS_ND];
    for (i = 0; i < PARAMS_ND; ++i) {
        DEBUG_OUT[i] = (uint16_t) U[i] & (PARAMS_P - 1);
    }
    print_sage_u_vector_matrix("r5_cpa_pke_decrypt: compressed U", DEBUG_OUT, PARAMS_K, PARAMS_M_BAR, PARAMS_N);
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT[i] = v[i];
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: compressed v", DEBUG_OUT, PARAMS_MU);
#endif

    // X' = U * S (mod p)
    ringmul_p(X_prime, U, S_idx);

#ifdef DEBUG
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT[i] = (uint16_t) (X_prime[i] & (PARAMS_P - 1));
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: X'", DEBUG_OUT, PARAMS_MU);
#endif

    // X' = v - X', compressed to 1 bit
    modp_t x_p;
    memset(m1, 0, sizeof (m1));
    for (i = 0; i < PARAMS_MU; i++) {
        // v - X' as mod p value (to be able to perform the rounding!)
        x_p = (modp_t) ((v[i] << (PARAMS_P_BITS - PARAMS_T_BITS)) - X_prime[i]);
#ifdef DEBUG
        DEBUG_OUT[i] = x_p & (PARAMS_P - 1);
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
    print_sage_u_vector("r5_cpa_pke_decrypt: uncompressed m2", DEBUG_OUT, PARAMS_MU);
    for (i = 0; i < PARAMS_MU; ++i) {
        DEBUG_OUT[i] = X_prime[i];
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: m2", DEBUG_OUT, PARAMS_MU);
    print_hex("r5_cpa_pke_decrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
#endif

#if (PARAMS_XE != 0)
    // Apply error correction
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
    xef_fixerr(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif
    memcpy(m, m1, PARAMS_KAPPA_BYTES);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    print_hex("r5_cpa_pke_decrypt: m", m, PARAMS_KAPPA_BYTES, 1);
#endif

    return 0;
}

#endif /* PARAMS_K == 1 */
