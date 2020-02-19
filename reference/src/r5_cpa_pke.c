/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the encryption functions used within the implementation.
 */

#include "r5_cpa_pke.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "r5_memory.h"
#include "r5_core.h"
#include "pack.h"
#include "rng.h"
#include "drbg.h"
#include "r5_hash.h"
#include "xef.h"

/*******************************************************************************
 * Private functions
 ******************************************************************************/

/**
 * Adds the value of the message to first len coefficients of a matrix.
 * The message is interpreted as a bit string where each group of bits_coeff
 * bits is first scaled by the scaling factor and then added to the
 * coefficient.
 *
 * @param[out] result         result of the addition
 * @param[in]  len            length of the result
 * @param[in]  matrix         matrix to which add the message
 * @param[in]  m              message to add
 * @param[in]  bits_coeff     number of bits added in each coefficient
 * @param[in]  scaling_factor scaling factor applied (also defines the modulo as 2^scaling_factor)
 * @return __0__ in case of success
 */
static int add_msg(uint16_t *result, const size_t len, const uint16_t *matrix, const unsigned char *m, const uint16_t bits_coeff, const uint8_t scaling_factor) {
    size_t i;
    int scale_shift = scaling_factor - bits_coeff;
    uint16_t val;
    size_t bits_done = 0;
    size_t idx;
    size_t bit_idx;

    /* Initialize result with coefficients in matrix */
    memcpy(result, matrix, len * sizeof (*matrix));

    for (i = 0; i < len; ++i) {
        idx = bits_done >> 3;
        bit_idx = bits_done & 7;
        val = (uint16_t) (m[idx] >> bit_idx);
        if (bit_idx + bits_coeff > 8) {
            /* Get spill over from next message byte */
            val = (uint16_t) (val | (m[idx + 1] << (8 - bit_idx)));
        }
        result[i] = (uint16_t) ((result[i] + (val << scale_shift)) & ((1 << scaling_factor) - 1));
        bits_done += bits_coeff;
    }

    return 0;
}

/**
 * Computes the difference of the first len coefficients of
 * matrix_a and matrix_b.
 *
 * @param[out] result         difference vector
 * @param[in]  len            length of the result
 * @param[in]  matrix_a       first operand
 * @param[in]  matrix_b       second operand
 * @param[in]  mod            the modulo in which to return the result (power of 2)
 * @return __0__ in case of success
 */
static int diff_msg(uint16_t *result, const size_t len, const uint16_t *matrix_a, const uint16_t *matrix_b, const uint16_t mod) {
    size_t i;

    for (i = 0; i < len; ++i) {
        result[i] = (uint16_t) ((matrix_a[i] - matrix_b[i]) & (mod - 1));
    }

    return 0;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cpa_pke_keygen(unsigned char *pk, unsigned char *sk Parameters) {
    unsigned char *sigma;
    uint16_t *A;
    int16_t *S;
    int16_t *S_T;
    uint16_t *B;
    size_t len_a;
    size_t len_s;
    size_t len_b;

    /* Calculate sizes */
    len_a = (size_t) (PARAMS_K * PARAMS_K * PARAMS_N);
    len_s = (size_t) (PARAMS_K * PARAMS_N_BAR * PARAMS_N);
    len_b = (size_t) (PARAMS_K * PARAMS_N_BAR * PARAMS_N);

    /* Allocate space */
    sigma = checked_malloc(PARAMS_KAPPA_BYTES);
    A = checked_malloc(len_a * sizeof (*A));
    S = checked_malloc(len_s * sizeof (*S));
    S_T = checked_malloc(len_s * sizeof (*S_T));
    B = checked_malloc(len_b * sizeof (*B));

    /* Generate seed sigma */
    randombytes(sigma, PARAMS_KAPPA_BYTES);

    /* Create A from sigma */
    create_A(A, sigma Params);

    /* Generate sk (seed) */
    randombytes(sk, PARAMS_KAPPA_BYTES);

    /* Generate S_T from sk */
    create_S_T(S_T, sk Params);

    /* Transpose S_T to get S */
    transpose_matrix((uint16_t *) S, (uint16_t *) S_T, PARAMS_N_BAR, PARAMS_K, PARAMS_N);

    /* B = A * S */
    mult_matrix(B, (int16_t *) A, PARAMS_K, PARAMS_K, S, PARAMS_K, PARAMS_N_BAR, PARAMS_N, PARAMS_Q, 0);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    printf("r5_cpa_pke_keygen: tau=%hhu\n", PARAMS_TAU);
    print_hex("r5_cpa_pke_keygen: sigma", sigma, PARAMS_KAPPA_BYTES, 1);
#ifdef DEBUG
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: A", A, PARAMS_K, PARAMS_K, PARAMS_N);
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: uncompressed B", B, PARAMS_K, PARAMS_N_BAR, PARAMS_N);
    print_sage_s_vector_matrix("r5_cpa_pke_keygen: S_T", S_T, PARAMS_N_BAR, PARAMS_K, PARAMS_N);
#endif
#endif

    /* Compress B q_bits -> p_bits with flooring */
    round_matrix(B, (size_t) (PARAMS_K * PARAMS_N_BAR), PARAMS_N, PARAMS_Q_BITS, PARAMS_P_BITS, PARAMS_H1);

    /* Serializing and packing */
    pack_pk(pk, sigma, PARAMS_KAPPA_BYTES, B, len_b, PARAMS_P_BITS);

    free(sigma);
    free(A);
    free(S);
    free(S_T);
    free(B);

    return 0;
}

int r5_cpa_pke_encrypt(unsigned char *ct, const unsigned char *pk, const unsigned char *m, const unsigned char *rho Parameters) {
    /* Seeds */
    unsigned char *sigma;

    /* Matrices, vectors, bit strings */
    uint16_t *A;
    uint16_t *A_T;
    int16_t *R;
    int16_t *R_T;
    uint16_t *U;
    uint16_t *U_T;
    uint16_t *B;
    uint16_t *B_T;
    uint16_t *X;
    uint16_t *v;
    uint8_t *m1;

    /* Length of matrices, vectors, bit strings */
    size_t len_a;
    size_t len_r;
    size_t len_u;
    size_t len_b;
    size_t len_x;
    size_t len_m1;

    len_a = (size_t) (PARAMS_K * PARAMS_K * PARAMS_N);
    len_r = (size_t) (PARAMS_K * PARAMS_M_BAR * PARAMS_N);
    len_u = (size_t) (PARAMS_K * PARAMS_M_BAR * PARAMS_N);
    len_b = (size_t) (PARAMS_K * PARAMS_N_BAR * PARAMS_N);
    len_x = (size_t) (PARAMS_N_BAR * PARAMS_M_BAR * PARAMS_N);
    len_m1 = (size_t) BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS);

    sigma = checked_malloc(PARAMS_KAPPA_BYTES);
    A = checked_malloc(len_a * sizeof (*A));
    A_T = checked_malloc(len_a * sizeof (*A_T));
    R = checked_malloc(len_r * sizeof (*R));
    R_T = checked_malloc(len_r * sizeof (*R_T));
    U = checked_malloc(len_u * sizeof (*U));
    U_T = checked_malloc(len_u * sizeof (*U_T));
    B = checked_malloc(len_b * sizeof (*B));
    B_T = checked_malloc(len_b * sizeof (*B_T));
    X = checked_malloc(len_x * sizeof (*X));
    v = checked_malloc(PARAMS_MU * sizeof (*v));
    m1 = checked_malloc(len_m1 * sizeof (*m1));

    /* Unpack received public key into sigma and B */
    unpack_pk(sigma, B, pk, PARAMS_KAPPA_BYTES, len_b, PARAMS_P_BITS);

    /* Create A from sigma */
    create_A(A, sigma Params);

    /* Create R_T from rho */
    create_R_T(R_T, rho Params);

    /* Transpose A */
    transpose_matrix(A_T, A, PARAMS_K, PARAMS_K, PARAMS_N);

    /* Transpose R_T to get R */
    transpose_matrix((uint16_t *) R, (uint16_t *) R_T, PARAMS_M_BAR, PARAMS_K, PARAMS_N);

    /* U = A^T * R */
    mult_matrix(U, (int16_t *) A_T, PARAMS_K, PARAMS_K, R, PARAMS_K, PARAMS_M_BAR, PARAMS_N, PARAMS_Q, 0);


#ifdef DEBUG
    print_hex("r5_cpa_pke_encrypt: m", m, PARAMS_KAPPA_BYTES, 1);
#endif
#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    print_hex("r5_cpa_pke_encrypt: rho", rho, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cpa_pke_encrypt: sigma", sigma, PARAMS_KAPPA_BYTES, 1);
#ifdef DEBUG
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: A", A, PARAMS_K, PARAMS_K, PARAMS_N);
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: B", B, PARAMS_K, PARAMS_N_BAR, PARAMS_N);
    print_sage_s_vector_matrix("r5_cpa_pke_encrypt: R_T", R_T, PARAMS_M_BAR, PARAMS_K, PARAMS_N);
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: uncompressed U", U, PARAMS_K, PARAMS_M_BAR, PARAMS_N);
#endif
#endif

    /* Compress U q_bits -> p_bits with flooring */
    round_matrix(U, (size_t) (PARAMS_K * PARAMS_M_BAR), PARAMS_N, PARAMS_Q_BITS, PARAMS_P_BITS, PARAMS_H2);

    /* Transpose U */
    transpose_matrix(U_T, U, PARAMS_K, PARAMS_M_BAR, PARAMS_N);

    /* Transpose B */
    transpose_matrix(B_T, B, PARAMS_K, PARAMS_N_BAR, PARAMS_N);

    /* X = B^T * R */
    mult_matrix(X, (int16_t *) B_T, PARAMS_N_BAR, PARAMS_K, R, PARAMS_K, PARAMS_M_BAR, PARAMS_N, PARAMS_P, PARAMS_XE != 0 || PARAMS_F != 0);
#ifdef DEBUG
    print_sage_u_vector("r5_cpa_pke_encrypt: uncompressed X", X, PARAMS_MU);
#endif

    /* v is a matrix of scalars, so we use 1 as the number of coefficients */
    round_matrix(X, PARAMS_MU, 1, PARAMS_P_BITS, PARAMS_T_BITS, PARAMS_H2);

    /* Compute codeword */
    memcpy(m1, m, PARAMS_KAPPA_BYTES);
    memset(m1 + PARAMS_KAPPA_BYTES, 0, (size_t) (len_m1 - PARAMS_KAPPA_BYTES));
    if (PARAMS_XE != 0) {
        xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
    }

    /* Add message (mod t) */
    add_msg(v, PARAMS_MU, X, m1, PARAMS_B_BITS, PARAMS_T_BITS);

    /* Transpose U */
    transpose_matrix(U_T, U, PARAMS_K, PARAMS_M_BAR, PARAMS_N);

    /* Pack ciphertext */
    pack_ct(ct, U_T, len_u, PARAMS_P_BITS, v, PARAMS_MU, PARAMS_T_BITS);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
#ifdef DEBUG
    print_sage_u_vector("r5_cpa_pke_encrypt: v", v, PARAMS_MU);
#endif
    print_hex("r5_cpa_pke_encrypt: m1", m1, len_m1, 1);
#endif

    free(sigma);
    free(A);
    free(A_T);
    free(R);
    free(R_T);
    free(U);
    free(U_T);
    free(B);
    free(B_T);
    free(X);
    free(v);
    free(m1);

    return 0;
}

int r5_cpa_pke_decrypt(unsigned char *m, const unsigned char *sk, const unsigned char *ct Parameters) {
    /* Matrices, vectors, bit strings */
    int16_t *S_T;
    uint16_t *U;
    uint16_t *U_T;
    uint16_t *v;
    uint16_t *X_prime;
    uint16_t *m2;
    uint8_t *m1;

    /* Length of matrices, vectors, bit strings */
    size_t len_s;
    size_t len_u;
    size_t len_x_prime;
    size_t len_m1;

    len_s = (size_t) (PARAMS_K * PARAMS_N_BAR * PARAMS_N);
    len_u = (size_t) (PARAMS_K * PARAMS_M_BAR * PARAMS_N);
    len_x_prime = (size_t) (PARAMS_N_BAR * PARAMS_M_BAR * PARAMS_N);

    S_T = checked_malloc(len_s * sizeof (*S_T));
    U = checked_malloc(len_u * sizeof (*U));
    U_T = checked_malloc(len_u * sizeof (*U));
    v = checked_malloc(PARAMS_MU * sizeof (*v));
    X_prime = checked_malloc(len_x_prime * sizeof (*X_prime));
    m2 = checked_malloc(PARAMS_MU * sizeof (*m2));

    /* Message plus error correction */
    len_m1 = (size_t) BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS);
    m1 = checked_calloc(len_m1, 1);

    /* Generate S_T from sk */
    create_S_T(S_T, sk Params);

    /* Unpack cipher text */
    unpack_ct(U_T, v, ct, len_u, PARAMS_P_BITS, PARAMS_MU, PARAMS_T_BITS);

    /* Transpose U^T */
    transpose_matrix(U, U_T, PARAMS_M_BAR, PARAMS_K, PARAMS_N);

#ifdef DEBUG
    print_sage_u_vector_matrix("r5_cpa_pke_decrypt: compressed U", U, PARAMS_K, PARAMS_M_BAR, PARAMS_N);
    print_sage_u_vector("r5_cpa_pke_decrypt: compressed v", v, PARAMS_MU);
#endif

    /* Decompress v t -> p */
    decompress_matrix(v, PARAMS_MU, 1, PARAMS_T_BITS, PARAMS_P_BITS);

    /* X' = S^T * U */
    mult_matrix(X_prime, S_T, PARAMS_N_BAR, PARAMS_K, (int16_t *) U, PARAMS_K, PARAMS_M_BAR, PARAMS_N, PARAMS_P, PARAMS_XE != 0 || PARAMS_F != 0);

#ifdef DEBUG
    print_sage_u_vector("r5_cpa_pke_decrypt: X'", X_prime, PARAMS_MU);
#endif

    /* v - X' (mod p) */
    diff_msg(m2, PARAMS_MU, v, X_prime, PARAMS_P);

#ifdef DEBUG
    print_sage_u_vector("r5_cpa_pke_decrypt: uncompressed m2", m2, PARAMS_MU);
#endif

    /* Compress msg p -> B */
    round_matrix(m2, PARAMS_MU, 1, PARAMS_P_BITS, PARAMS_B_BITS, PARAMS_H3);

#ifdef DEBUG
    print_sage_u_vector("r5_cpa_pke_decrypt: m2", m2, PARAMS_MU);
#endif

    /* Convert the message to bit string format */
    pack(m1, m2, PARAMS_MU, PARAMS_B_BITS);

#ifdef DEBUG
    print_hex("r5_cpa_pke_decrypt: m1", m1, len_m1, 1);
#endif

    if (PARAMS_XE != 0) {
        xef_compute(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
        xef_fixerr(m1, PARAMS_KAPPA_BYTES, PARAMS_F);
    }
    memcpy(m, m1, PARAMS_KAPPA_BYTES);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    print_hex("r5_cpa_pke_decrypt: m", m, PARAMS_KAPPA_BYTES, 1);
#endif

    free(S_T);
    free(U);
    free(U_T);
    free(v);
    free(X_prime);
    free(m2);
    free(m1);

    return 0;
}
