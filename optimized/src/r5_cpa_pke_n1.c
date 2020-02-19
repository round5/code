/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include "r5_cpa_pke.h"
#include "r5_parameter_sets.h"

#if PARAMS_K != 1

#include "r5_hash.h"
#include "rng.h"
#include "xef.h"
#include "matmul.h"
#include "r5_secretkeygen.h"
#include "misc.h"
#include "a_random.h"
#include "pack.h"

#ifdef DEBUG
#if PARAMS_TAU==0
#define A_element(r,c) A_random[r][c]
#elif PARAMS_TAU == 1
#define A_element(r,c) A_fixed[A_permutation[r] + (uint32_t) c]
#elif PARAMS_TAU == 2
#define A_element(r,c) A_random[A_permutation[r] + (uint16_t) c]
#endif
#endif


#if PARAMS_TAU != 0
#include "little_endian.h"
#include "drbg.h"
//The DRBG customization when creating the tau=1 or tau=2 permutations.
static const uint8_t permutation_customization[2] = {0, 1};
#endif

#if PARAMS_TAU == 1

#include "a_fixed.h"

static int create_A_permutation(uint32_t A_permutation[PARAMS_D], const unsigned char *sigma) {
   
    uint16_t rnd;
    
    drbg_init_customization(sigma, permutation_customization, sizeof (permutation_customization));
    
    for (uint32_t i = 0; i < PARAMS_D; ++i) {
        do {
            one_uint16_t_customization(rnd);
        } while (rnd >= PARAMS_RS_LIM);
        rnd = (uint16_t) (rnd / PARAMS_RS_DIV);
        A_permutation[i] = 2 * i * PARAMS_D + rnd;
    }

    return 0;
}

#elif PARAMS_TAU == 2

static int create_A_permutation(uint16_t A_permutation[PARAMS_D], const unsigned char *sigma) {
   
    uint16_t rnd;
    uint32_t i;
    uint8_t v[PARAMS_TAU2_LEN] = {0};

    drbg_init_customization(sigma, permutation_customization, sizeof (permutation_customization));

    for (i = 0; i < PARAMS_D; ++i) {
        do {
            one_uint16_t_customization(rnd);
            rnd = (uint16_t) (rnd & (PARAMS_TAU2_LEN - 1));
        } while (v[rnd]);
        v[rnd] = 1;
        A_permutation[i] = rnd;
    }

    return 0;
}

#endif

// generate a keypair (sigma, B)
int r5_cpa_pke_keygen(uint8_t *pk, uint8_t *sk) {
    
    modq_t B[PARAMS_D][PARAMS_N_BAR];
    tern_secret_s S_T;
    
    
    randombytes(pk, PARAMS_KAPPA_BYTES); // sigma = seed of (permutation of) A
#if PARAMS_TAU == 0
    modq_t A_random[PARAMS_D][PARAMS_D];
    create_A_random((modq_t *) A_random, pk);
    #define A_matrix A_random
#elif PARAMS_TAU == 1
    uint32_t A_permutation[PARAMS_D];
    create_A_permutation(A_permutation, pk);
    #define A_matrix A_fixed
#elif PARAMS_TAU == 2
    modq_t A_random[PARAMS_TAU2_LEN + PARAMS_D];
    create_A_random(A_random, pk);
    size_t i;
    for (i=0; i < PARAMS_D; i++) {A_random[PARAMS_TAU2_LEN + i] = A_random[i];} //memcpy(A_random + PARAMS_TAU2_LEN, A_random, PARAMS_D * sizeof (modq_t));
    uint16_t A_permutation[PARAMS_D];
    create_A_permutation(A_permutation, pk);
    #define A_matrix A_random
#endif
    
    // secret key -- Random S
    randombytes(sk, PARAMS_KAPPA_BYTES);
    create_secret_matrix_s_t(S_T, sk);
    
    // B = A * S
#if PARAMS_TAU == 0
    matmul_as_q(B, A_matrix, S_T);
#else
    matmul_as_q(B, A_matrix, A_permutation, S_T);
#endif
    // Compress B q_bits -> p_bits, pk = sigma | B
    pack_qp(pk + PARAMS_KAPPA_BYTES, &B[0][0], PARAMS_H1, PARAMS_D * PARAMS_N_BAR, (size_t) BITS_TO_BYTES(PARAMS_P_BITS * PARAMS_D * PARAMS_N_BAR));
    
    DEBUG_PRINT(
        printf("r5_cpa_pke_keygen: tau=%u\n", PARAMS_TAU);
        print_hex("r5_cpa_pke_keygen: sigma", pk, PARAMS_KAPPA_BYTES, 1);
        uint16_t debug_A[PARAMS_D][PARAMS_D];
        for (int i = 0; i < PARAMS_D; ++i) {
            for (int j = 0; j < PARAMS_D; ++j) {
                debug_A[i][j] = (uint16_t) (A_element(i, j) & (PARAMS_Q - 1));
            }
        }
        //print_sage_u_vector_matrix("r5_cpa_pke_keygen: A", &debug_A[0][0], PARAMS_K, PARAMS_K, PARAMS_N);

        uint16_t debug_B[PARAMS_D][PARAMS_N_BAR];
        for (int i = 0; i < PARAMS_D; ++i) {
            for (int j = 0; j < PARAMS_N_BAR; ++j) {
                debug_B[i][j] = (uint16_t) (B[i][j] & (PARAMS_Q - 1));
            }
        }

        //print_sage_u_vector_matrix("r5_cpa_pke_keygen: uncompressed B", &debug_B[0][0], PARAMS_K, PARAMS_N_BAR, PARAMS_N);
    )
    
    return 0;
}

int r5_cpa_pke_encrypt(uint8_t *ct, const uint8_t *pk, const uint8_t *m, const uint8_t *rho) {
    
    size_t i, j;
    tern_secret_r R_T;
    modq_t U_T[PARAMS_M_BAR][PARAMS_D];
    modp_t B[PARAMS_D][PARAMS_N_BAR];
    modp_t X[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];
    modp_t t, tm;

    unpack_p(&B[0][0], pk + PARAMS_KAPPA_BYTES, PARAMS_D*PARAMS_N_BAR);

    #undef A_matrix
#if PARAMS_TAU == 0
    modq_t A_random[PARAMS_D][PARAMS_K];
    create_A_random((modq_t *) A_random, pk);
    #define A_matrix A_random
#elif PARAMS_TAU == 1
    uint32_t A_permutation[PARAMS_D];
    create_A_permutation(A_permutation, pk);
    #define A_matrix A_fixed
#elif PARAMS_TAU == 2
    modq_t A_random[PARAMS_TAU2_LEN + PARAMS_D];
    create_A_random(A_random, pk);
    for (i=0; i < PARAMS_D ; i++) {A_random[PARAMS_TAU2_LEN + i] = A_random[i];} //memcpy(A_random + PARAMS_TAU2_LEN, A_random, PARAMS_D * sizeof (modq_t));
    uint16_t A_permutation[PARAMS_D];
    create_A_permutation(A_permutation, pk);
    #define A_matrix A_random
#endif
    
    for (i=0; i < PARAMS_KAPPA_BYTES; i++) {m1[i] = m[i];} //
    //memcpy(m1, m, PARAMS_KAPPA_BYTES);
    for (i=PARAMS_KAPPA_BYTES; i <  BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS) ; i++) {m1[i] = 0;} //
    //memset(m1 + PARAMS_KAPPA_BYTES, 0, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS) - PARAMS_KAPPA_BYTES);

#if (PARAMS_XE != 0)
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif

    create_secret_matrix_r_t(R_T, rho); // Create R

#if PARAMS_TAU == 0
    matmul_rta_q(U_T, A_matrix, R_T); // U^T = (R^T x A)^T   (mod q)
#else
    matmul_rta_q(U_T, A_matrix, A_permutation, R_T);
#endif
    
    matmul_btr_p(X, B, R_T); // X = R^T x B   (mod p)

    pack_qp(ct, &U_T[0][0], PARAMS_H2, PARAMS_D * PARAMS_M_BAR,(size_t) BITS_TO_BYTES(PARAMS_P_BITS * PARAMS_D * PARAMS_M_BAR));
    
    for (i=0; i < PARAMS_MUT_SIZE; i++) {ct[PARAMS_DPU_SIZE+i]=0;} // memset(ct + PARAMS_DPU_SIZE, 0, PARAMS_MUT_SIZE);
    
    j = 8 * PARAMS_DPU_SIZE;

    for (i = 0; i < PARAMS_MU; i++) { // compute, pack v
        t = (modp_t) ((X[i] + PARAMS_H2) >> (PARAMS_P_BITS - PARAMS_T_BITS)); // compress p->t
        tm = (modp_t) (m1[(i * PARAMS_B_BITS) >> 3] >> ((i * PARAMS_B_BITS) & 7)); // add message
        
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
    
    DEBUG_PRINT(
        print_hex("r5_cpa_pke_encrypt: m", m, PARAMS_KAPPA_BYTES, 1);
        print_hex("r5_cpa_pke_encrypt: rho", rho, PARAMS_KAPPA_BYTES, 1);
        print_hex("r5_cpa_pke_encrypt: sigma", pk, PARAMS_KAPPA_BYTES, 1);
        modq_t DEBUG_OUT_A[PARAMS_D][PARAMS_D];
        for (int i = 0; i < PARAMS_D; ++i) {
            for (int j = 0; j < PARAMS_D; ++j) {
                DEBUG_OUT_A[i][j] = (uint16_t) (A_element(i, j) & (PARAMS_Q - 1));
            }
        }
        
        //print_sage_u_vector_matrix("r5_cpa_pke_encrypt: A", &DEBUG_OUT_A[0][0], PARAMS_K, PARAMS_K, PARAMS_N);
                
        //print_sage_u_vector_matrix("r5_cpa_pke_encrypt: B", &B[0][0], PARAMS_K, PARAMS_N_BAR, PARAMS_N);
        
        uint16_t debug_u[PARAMS_D][PARAMS_M_BAR];
        for (i = 0; i < PARAMS_D; ++i) {
            for (j = 0; j < PARAMS_M_BAR; ++j) {
                debug_u[i][j] = (uint16_t) (U_T[j][i] & (PARAMS_Q - 1));
            }
        }
        print_sage_u_vector_matrix("r5_cpa_pke_encrypt: uncompressed U", &debug_u[0][0], PARAMS_K, PARAMS_M_BAR, PARAMS_N);
        
        uint16_t debug_x[PARAMS_MU];
        for (i = 0; i < PARAMS_MU; ++i) {
            debug_x[i] = (uint16_t) (X[i] & (PARAMS_P - 1));
        }
        print_sage_u_vector("r5_cpa_pke_encrypt: uncompressed X", debug_x, PARAMS_MU);
        print_hex("r5_cpa_pke_encrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
    
    )

    return 0;
}

int r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
    size_t i, j;
    
    tern_secret_s S_T;

    modp_t U_T[PARAMS_M_BAR][PARAMS_D];
    modp_t v[PARAMS_MU];
    modp_t t, X_prime[PARAMS_MU];
    uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)] = {0};

    create_secret_matrix_s_t(S_T, sk);

    unpack_p((modp_t *) U_T, ct, PARAMS_D*PARAMS_M_BAR);

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
    
    matmul_stu_p(X_prime, U_T, S_T); // X' = S^T * U (mod p)

    modp_t x_p;
    
    for (i = 0; i < PARAMS_MU; i++) {
        // v - X' as mod q value (to be able to perform the rounding!)
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
    
#if (PARAMS_XE != 0) // Apply error correction
    xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
    xef_fixerr(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
#endif
    
    for (i=0; i < PARAMS_KAPPA_BYTES; i++) {m[i] = m1[i];}//memcpy(m, m1, PARAMS_KAPPA_BYTES);

    DEBUG_PRINT(
        uint16_t DEBUG_OUT_U[PARAMS_D][PARAMS_M_BAR];
        for (i = 0; i < PARAMS_D; ++i) {
            for (j = 0; j < PARAMS_M_BAR; ++j) {
                DEBUG_OUT_U[i][j] = U_T[j][i] & (PARAMS_P - 1);
            }
        }
        print_sage_u_vector_matrix("r5_cpa_pke_decrypt: compressed U", &DEBUG_OUT_U[0][0], PARAMS_K, PARAMS_M_BAR, PARAMS_N);

        uint16_t DEBUG_OUT_v[PARAMS_MU];
        for (i = 0; i < PARAMS_MU; ++i) {
            DEBUG_OUT_v[i] = v[i];
        }
        print_sage_u_vector("r5_cpa_pke_decrypt: compressed v", DEBUG_OUT_v, PARAMS_MU);
        print_hex("r5_cpa_pke_decrypt: m1", m1, BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS), 1);
        print_hex("r5_cpa_pke_decrypt: m", m, PARAMS_KAPPA_BYTES, 1);
    )

    return 0;
}

#endif /* PARAMS_K != 1 */
