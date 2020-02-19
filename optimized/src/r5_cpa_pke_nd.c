/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#include "r5_cpa_pke.h"
#include "r5_parameter_sets.h"

#if PARAMS_K == 1

#include "r5_hash.h"
#include "rng.h"
#include "xef.h"
#include "ringmul.h"
#include "r5_secretkeygen.h"
#include "misc.h"
#include "a_random.h"
#include "pack.h"

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
#elif PARAMS_F == 4 && PARAMS_XE == 163
#define XEF(function, block, len, f) xe4_163_##function(block)
#elif PARAMS_F == 2 && PARAMS_XE == 53
#define XEF(function, block, len, f) xe2_53_##function(block)
#else
#define XEF(function, block, len, f) xef_##function(block, len, f)
#endif
#define xef_compute(block, len, f) XEF(compute, block, len, f)
#define xef_fixerr(block, len, f) XEF(fixerr, block, len, f)

#endif

// generate a keypair (sigma, B)
int r5_cpa_pke_keygen(uint8_t *pk, uint8_t *sk) {
    modq_t A[PARAMS_N];
    modq_t B[PARAMS_N];
    tern_secret S_idx;

    randombytes(pk, PARAMS_KAPPA_BYTES); // sigma = seed of A

    // A from sigma
    create_A_random(A, pk);

    randombytes(sk, PARAMS_KAPPA_BYTES); // secret key -- Random S
    create_secret_vector(S_idx, sk);
    
    // B = A * S
    ringmul_q(B, A, S_idx);
    
    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_qp(pk + PARAMS_KAPPA_BYTES, B, PARAMS_H1, PARAMS_N, PARAMS_DP_SIZE);

    DEBUG_PRINT(
        printf("r5_cpa_pke_keygen: tau=%u\n", PARAMS_TAU);
        print_hex("r5_cpa_pke_keygen: sigma", pk, PARAMS_KAPPA_BYTES, 1);
        for (int i = 0; i < PARAMS_N; ++i) {
            A[i] = (uint16_t) (A[i] & (PARAMS_Q - 1));
        }
        print_sage_u_vector_matrix("r5_cpa_pke_keygen: A", A, PARAMS_K, PARAMS_K, PARAMS_N);
        for (int i = 0; i < PARAMS_N; ++i) {
            B[i] = (uint16_t) (B[i] & (PARAMS_Q - 1));
        }
        print_sage_u_vector_matrix("r5_cpa_pke_keygen: uncompressed B", B, PARAMS_K, PARAMS_N_BAR, PARAMS_N);)

    return 0;
}

int r5_cpa_pke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t *m, const uint8_t *rho) {
    size_t i, j;
    modp_t t, tm;
    modq_t A[PARAMS_N];
    tern_secret R_idx;
    modq_t U_T[PARAMS_N];
    modp_t B[PARAMS_N];
    modp_t X[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)] = {0};
    
    // unpack public key
    unpack_p(B, pk + PARAMS_KAPPA_BYTES, PARAMS_N);

    // A from sigma
    create_A_random(A, pk);
    
    for (i = 0; i < PARAMS_KAPPA_BYTES; i++) {m1[i] = m[i];}
    
#if (PARAMS_XE != 0)
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif

    // Create R
    create_secret_vector(R_idx, rho);

    ringmul_q(U_T, A, R_idx); // U^T == U = A^T * R == A * R (mod q)
    ringmul_p(X, B, R_idx); // X = B^T * R == B * R (mod p)


    //pack_q_p(ct, U_T, PARAMS_H2);
    pack_qp(ct, U_T, PARAMS_H2, PARAMS_N, PARAMS_DP_SIZE); // ct = U^T | v
    
    for (i = 0; i < PARAMS_MUT_SIZE; i++) {ct[i+PARAMS_DP_SIZE] = 0;}
    
    j = 8 * PARAMS_DP_SIZE;
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

    DEBUG_PRINT(
        print_hex("r5_cpa_pke_encrypt: m", m, PARAMS_KAPPA_BYTES, 1);
        print_hex("r5_cpa_pke_encrypt: rho", rho, PARAMS_KAPPA_BYTES, 1);
        print_hex("r5_cpa_pke_encrypt: sigma", pk, PARAMS_KAPPA_BYTES, 1);
        for (i = 0; i < PARAMS_N; ++i) {
            A[i] &= (PARAMS_Q - 1);
        }
        print_sage_u_vector_matrix("r5_cpa_pke_encrypt: A", A, PARAMS_K, PARAMS_K, PARAMS_N);
        uint16_t debug_out[PARAMS_N];
        for (i = 0; i < PARAMS_N; ++i) {
            debug_out[i] = B[i];
        }
        print_sage_u_vector_matrix("r5_cpa_pke_encrypt: B", debug_out, PARAMS_K, PARAMS_N_BAR, PARAMS_N);
        for (i = 0; i < PARAMS_N; ++i) {
            debug_out[i] = (uint16_t) (U_T[i] & (PARAMS_Q - 1));
        }
        print_sage_u_vector_matrix("r5_cpa_pke_encrypt: uncompressed U", debug_out, PARAMS_K, PARAMS_M_BAR, PARAMS_N);

        for (i = 0; i < PARAMS_MU; ++i) {
            debug_out[i] = (uint16_t) (X[i] & (PARAMS_P - 1));
        }
        print_sage_u_vector("r5_cpa_pke_encrypt: uncompressed X", debug_out, PARAMS_MU);
        print_hex("r5_cpa_pke_encrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
    )

    return 0;
}

int r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
    size_t i, j;
    tern_secret S_idx;
    modp_t x_p;
    modp_t U_T[PARAMS_N];
    modp_t v[PARAMS_MU];
    modp_t t, X_prime[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)] = {0};

    create_secret_vector(S_idx, sk);

    unpack_p(U_T, ct, PARAMS_N);// ct = U^T | v

    j = 8 * PARAMS_DP_SIZE;
    for (i = 0; i < PARAMS_MU; i++) {
        t = (modp_t) (ct[j >> 3] >> (j & 7)); // unpack t bits
        if ((j & 7) + PARAMS_T_BITS > 8) {
            t = (modp_t) (t | ct[(j >> 3) + 1] << (8 - (j & 7)));
        }
        v[i] = t & ((1 << PARAMS_T_BITS) - 1);
        j += PARAMS_T_BITS;
    }

    ringmul_p(X_prime, U_T, S_idx); // X' = S^T * U == U^T * S (mod p)

    // X' = v - X', compressed to 1 bit
    for (i = 0; i < PARAMS_MU; i++) {
        // v - X' as mod p value (to be able to perform the rounding!)
        x_p = (modp_t) ((v[i] << (PARAMS_P_BITS - PARAMS_T_BITS)) - X_prime[i]);
        x_p = (modp_t) (((x_p + PARAMS_H3) >> (PARAMS_P_BITS - PARAMS_B_BITS)) & ((1 << PARAMS_B_BITS) - 1));

        m1[i * PARAMS_B_BITS >> 3] = (uint8_t) (m1[i * PARAMS_B_BITS >> 3] | (x_p << ((i * PARAMS_B_BITS) & 7)));
        
#if (8 % PARAMS_B_BITS != 0)
        if (((i * PARAMS_B_BITS) & 7) + PARAMS_B_BITS > 8) {
            /* Spill over to next message byte */
            m1[(i * PARAMS_B_BITS >> 3) + 1] = (uint8_t) (m1[(i * PARAMS_B_BITS >> 3) + 1] | (x_p >> (8 - ((i * PARAMS_B_BITS) & 7))));
        }
#endif
    }

#if (PARAMS_XE != 0)
    // Apply error correction
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
    xef_fixerr(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif

    for (i = 0; i < PARAMS_KAPPA_BYTES; i++) {m[i] = m1[i];}

    DEBUG_PRINT(
        uint16_t DEBUG_OUT[PARAMS_N];
        for (i = 0; i < PARAMS_N; ++i) {
            DEBUG_OUT[i] = (uint16_t) U_T[i] & (PARAMS_P - 1);
        }
        print_sage_u_vector_matrix("r5_cpa_pke_decrypt: compressed U", DEBUG_OUT, PARAMS_K, PARAMS_M_BAR, PARAMS_N);
        for (i = 0; i < PARAMS_MU; ++i) {
            DEBUG_OUT[i] = v[i];
        }
        print_sage_u_vector("r5_cpa_pke_decrypt: compressed v", DEBUG_OUT, PARAMS_MU);
   
        for (i = 0; i < PARAMS_MU; ++i) {
            DEBUG_OUT[i] = (uint16_t) (X_prime[i] & (PARAMS_P - 1));
        }
        print_sage_u_vector("r5_cpa_pke_decrypt: X'", DEBUG_OUT, PARAMS_MU);
    
        print_hex("r5_cpa_pke_decrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
        print_hex("r5_cpa_pke_decrypt: m", m, PARAMS_KAPPA_BYTES, 1);
    )
    
    return 0;
}

#endif /* PARAMS_K == 1 */
