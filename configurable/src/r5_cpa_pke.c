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

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

/**
 * Wrapper around the xef functions so we can seamlessly make use of the optimized xe5.
 *
 * @param function the xef function to wrap (i.e. `compute` or `fixerr`)
 */
#define WRAP_XEF(function) void _xef_##function(void *block, size_t len, unsigned f) { \
    if (f == 5) { \
        switch(len) { \
            case 16: xe5_190_##function(block); break; \
            case 24: xe5_218_##function(block); break; \
            case 32: xe5_234_##function(block); break; \
        } \
    } else if (f == 4 && len == 24) { \
        xe4_163_##function(block); \
    } else if (f == 2 && len == 16) { \
        xe2_53_##function(block); \
    } else { \
        xef_##function(block, len, f); \
    } \
}

WRAP_XEF(compute)
WRAP_XEF(fixerr)

/**
 * Computes the error correction bits.
 *
 * @param block the block to compute the error correction for
 * @param len the length of the block excluding the bits for error correction (must be 16, 24, or 32)
 * @param f the number of bits to correct (0..5)
 * @return the length of the block including the error correction bits in *bits*
 */
#define xef_compute(block, len, f) _xef_compute(block, len, f)

/**
 * Applies the error correction bits.
 *
 * @param block the block to apply the error correction to
 * @param len the length of the block excluding the bits for error correction (must be 16, 24, or 32)
 * @param f the number of bits to correct (0..5)
 * @return the length of the block including the error correction bits in *bits*
 */
#define xef_fixerr(block, len, f) _xef_fixerr(block, len, f)

#endif

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
        result[i] = (uint16_t) (result[i] + (val << scale_shift));
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
 * @return __0__ in case of success
 */
static int diff_msg(uint16_t *result, const size_t len, const uint16_t *matrix_a, const uint16_t *matrix_b) {
    size_t i;

    for (i = 0; i < len; ++i) {
        result[i] = (uint16_t) (matrix_a[i] - matrix_b[i]);
    }

    return 0;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cpa_pke_keygen(unsigned char *pk, unsigned char *sk, const parameters *params) {
    unsigned char *sigma;
    uint16_t *A;
    uint32_t *A_permutation;
    uint16_t *S_idx;
    uint16_t *B;
    size_t len_s_idx;
    size_t len_b;

    /* Calculate sizes */
    len_s_idx = (size_t) (params->h * params->n_bar);
    len_b = (size_t) (params->k * params->n_bar * params->n);

    /* Allocate space */
    sigma = checked_malloc(params->kappa_bytes);
    A_permutation = checked_malloc((size_t) (params->d + 1) * sizeof (*A_permutation));
    S_idx = checked_malloc(len_s_idx * sizeof (*S_idx));
    B = checked_malloc(len_b * sizeof (*B));

    /* Generate seed sigma */
    randombytes(sigma, params->kappa_bytes);

    /* Create A from sigma */
    create_A(&A, A_permutation, sigma, params);

    /* Generate sk (seed) */
    randombytes(sk, params->kappa_bytes);

    /* Generate S from sk */
    create_S(S_idx, sk, params);

    /* B = A * S */
    compute_AS(B, A, A_permutation, S_idx, params);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    printf("r5_cpa_pke_keygen: tau=%hhu\n", params->tau);
    print_hex("r5_cpa_pke_keygen: sigma", sigma, params->kappa_bytes, 1);
#ifdef DEBUG
    uint16_t *DEBUG_OUT = checked_calloc((size_t) (params->k * params->d), sizeof (*A));
    if (params->k == 1) {
        uint16_t *aux = checked_malloc(((size_t) (params->d + 1) * sizeof (*A)));
        aux[0] = A[0];
        for (size_t i = 1; i < (size_t) (params->d + 1); ++i) {
            aux[i] = A[(size_t) (params->d + 1) - i];
        }
        unlift_poly(DEBUG_OUT, aux, params->d);
        free(aux);
    } else {
        for (size_t i = 0; i < params->d; ++i) {
            for (size_t j = 0; j < params->d; ++j) {
                DEBUG_OUT[i * params->d + j] = A[(j + A_permutation[i])];
            }
        }
    }
    for (size_t i = 0; i < (size_t) (params->k * params->d); ++i) {
        DEBUG_OUT[i] = (uint16_t) (DEBUG_OUT[i] & (params->q - 1));
    }
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: A", DEBUG_OUT, params->k, params->k, params->n);
    free(DEBUG_OUT);
    for (size_t i = 0; i < len_b; ++i) {
        B[i] = (uint16_t) (B[i] & (params->q - 1));
    }
    print_sage_u_vector_matrix("r5_cpa_pke_keygen: uncompressed B", B, params->k, params->n_bar, params->n);
    int16_t *S_T;
    S_T = checked_calloc((size_t) (params->d * params->n_bar), sizeof (*S_T));
    for (size_t j = 0; j < params->n_bar; ++j) {
        for (size_t i = 0; i < (size_t) (params->h / 2); ++i) {
            S_T[j * params->d + S_idx[j * params->h + i]] = 1;
        }
        for (size_t i = (size_t) (params->h / 2); i < params->h; ++i) {
            S_T[j * params->d + S_idx[j * params->h + i]] = -1;
        }
    }
    print_sage_s_vector_matrix("r5_cpa_pke_keygen: S_T", S_T, params->n_bar, params->k, params->n);
    free(S_T);
#endif
#endif

    /* Compress B q_bits -> p_bits */
    round_matrix(B, (size_t) (params->k * params->n_bar), params->n, params->q_bits, params->p_bits, params->h1);

    /* Serializing and packing */
    pack_pk(pk, sigma, params->kappa_bytes, B, len_b, params->p_bits);

    free(sigma);
    if (params->tau != 1) {
        free(A);
    }
    free(A_permutation);
    free(S_idx);
    free(B);

    return 0;
}

int r5_cpa_pke_encrypt(unsigned char *ct, const unsigned char *pk, const unsigned char *m, const unsigned char *rho, const parameters *params) {
    /* Seeds */
    unsigned char *sigma;

    /* Matrices, vectors, bit strings */
    uint16_t *A;
    uint32_t *A_permutation;
    uint16_t *R_idx;
    uint16_t *U_T;
    uint16_t *B;
    uint16_t *X;
    uint16_t *v;
    uint8_t *m1;

    /* Length of matrices, vectors, bit strings */
    size_t len_r_idx;
    size_t len_u;
    size_t len_b;
    size_t len_x;
    size_t len_m1;

    len_r_idx = (size_t) (params->h * params->m_bar);
    len_u = (size_t) (params->m_bar * params->d);
    len_b = (size_t) (params->d * params->n_bar);
    len_x = (size_t) (params->n_bar * params->m_bar * params->n);
    len_m1 = (size_t) BITS_TO_BYTES(params->mu * params->b_bits);

    sigma = checked_malloc(params->kappa_bytes);
    B = checked_malloc(len_b * sizeof (*B));
    R_idx = checked_malloc(len_r_idx * sizeof (*R_idx));
    U_T = checked_malloc(len_u * sizeof (*U_T));
    X = checked_malloc(len_x * sizeof (*X));
    v = checked_malloc(params->mu * sizeof (*v));
    m1 = checked_malloc(len_m1 * sizeof (*m1));

    /* Unpack received public key into tau, sigma and B */
    unpack_pk(sigma, B, pk, params->kappa_bytes, len_b, params->p_bits);

    /* Create A from sigma */
    A_permutation = checked_malloc((size_t) (params->d + 1) * sizeof (*A_permutation));
    create_A(&A, A_permutation, sigma, params);

    /* Create R from rho */
    create_R(R_idx, rho, params);

    /* U^T = (A^T * R)^T = R^T * A */
    compute_RTA(U_T, A, A_permutation, R_idx, params);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
#ifdef DEBUG
    print_hex("r5_cpa_pke_encrypt: m", m, params->kappa_bytes, 1);
#endif
    print_hex("r5_cpa_pke_encrypt: rho", rho, params->kappa_bytes, 1);
    print_hex("r5_cpa_pke_encrypt: sigma", sigma, params->kappa_bytes, 1);
#ifdef DEBUG
    uint16_t *DEBUG_OUT = checked_calloc((size_t) (params->k * params->d), sizeof (*A));
    if (params->k == 1) {
        uint16_t *aux = checked_malloc(((size_t) (params->d + 1) * sizeof (*A)));
        aux[0] = A[0];
        for (size_t i = 1; i < (size_t) (params->d + 1); ++i) {
            aux[i] = A[(size_t) (params->d + 1) - i];
        }
        unlift_poly(DEBUG_OUT, aux, params->d);
        free(aux);
    } else {
        for (size_t i = 0; i < params->d; ++i) {
            for (size_t j = 0; j < params->d; ++j) {
                DEBUG_OUT[i * params->d + j] = A[(j + A_permutation[i])];
            }
        }
    }
    for (size_t i = 0; i < (size_t) (params->k * params->d); ++i) {
        DEBUG_OUT[i] = (uint16_t) (DEBUG_OUT[i] & (params->q - 1));
    }
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: A", DEBUG_OUT, params->k, params->k, params->n);
    free(DEBUG_OUT);
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: B", B, params->k, params->n_bar, params->n);
    int16_t *R_T = checked_calloc((size_t) (params->d * params->m_bar), sizeof (*R_T));
    for (size_t j = 0; j < params->m_bar; ++j) {
        for (size_t i = 0; i < (size_t) (params->h / 2); ++i) {
            R_T[j * params->d + R_idx[j * params->h + i]] = 1;
        }
        for (size_t i = (size_t) (params->h / 2); i < params->h; ++i) {
            R_T[j * params->d + R_idx[j * params->h + i]] = -1;
        }
    }
    print_sage_s_vector_matrix("r5_cpa_pke_encrypt: R_T", R_T, params->m_bar, params->k, params->n);
    uint16_t *U = checked_malloc(len_u * sizeof (*U));
    for (size_t i = 0; i < params->m_bar; ++i) {
        for (size_t j = 0; j < params->k; ++j) {
            for (size_t k = 0; k < params->n; ++k) {
                U[j * (size_t) (params->m_bar * params->n) + (size_t) (i * params->n) + k] = (uint16_t) (U_T[i * (size_t) (params->k * params->n) + (size_t) (j * params->n) + k] & (params->q - 1));
            }
        }
    }
    print_sage_u_vector_matrix("r5_cpa_pke_encrypt: uncompressed U", U, params->k, params->m_bar, params->n);
    free(R_T);
    free(U);
#endif
#endif

    /* Compress U q_bits -> p_bits */
    round_matrix(U_T, (size_t) (params->k * params->m_bar), params->n, params->q_bits, params->p_bits, params->h2);

    /* X = B * R == R_T * B */
    compute_BTR(X, B, R_idx, params);
#ifdef DEBUG
    for (size_t i = 0; i < params->mu; ++i) {
        X[i] = (uint16_t) (X[i] & (params->p - 1));
    }
    print_sage_u_vector("r5_cpa_pke_encrypt: uncompressed X", X, params->mu);
#endif

    /* v is a matrix of scalars, so we use 1 as the number of coefficients */
    round_matrix(X, params->mu, 1, params->p_bits, params->t_bits, params->h2);

    /* Compute codeword */
    memcpy(m1, m, params->kappa_bytes);
    memset(m1 + params->kappa_bytes, 0, (size_t) (len_m1 - params->kappa_bytes));
    if (params->xe != 0) {
        xef_compute(m1, params->kappa_bytes, params->f);
    }

    /* Add message */
    add_msg(v, params->mu, X, m1, params->b_bits, params->t_bits);

    /* Pack ciphertext */
    pack_ct(ct, U_T, len_u, params->p_bits, v, params->mu, params->t_bits);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
#ifdef DEBUG
    for (size_t i = 0; i < params->mu; ++i) {
        v[i] = (uint16_t) (v[i] & ((1 << params->t_bits) - 1));
    }
    print_sage_u_vector("r5_cpa_pke_encrypt: v", v, params->mu);
#endif
    print_hex("r5_cpa_pke_encrypt: m1", m1, len_m1, 1);
#endif

    free(sigma);
    if (params->tau != 1) {
        free(A);
    }
    free(A_permutation);
    free(R_idx);
    free(U_T);
    free(B);
    free(X);
    free(v);
    free(m1);

    return 0;
}

int r5_cpa_pke_decrypt(unsigned char *m, const unsigned char *sk, const unsigned char *ct, const parameters *params) {
    /* Matrices, vectors, bit strings */
    uint16_t *S_idx;
    uint16_t *U_T;
    uint16_t *v;
    uint16_t *X_prime;
    uint16_t *m2;
    uint8_t *m1;

    /* Length of matrices, vectors, bit strings */
    size_t len_s_idx;
    size_t len_u;
    size_t len_x_prime;
    size_t len_m1;


    len_s_idx = (size_t) (params->h * params->n_bar);
    len_u = (size_t) (params->d * params->m_bar);
    len_x_prime = params->mu;
    len_m1 = (size_t) BITS_TO_BYTES(params->mu * params->b_bits);

    S_idx = checked_malloc(len_s_idx * sizeof (*S_idx));
    U_T = checked_malloc(len_u * sizeof (*U_T));
    v = checked_malloc(params->mu * sizeof (*v));
    X_prime = checked_malloc(len_x_prime * sizeof (*X_prime));
    m1 = checked_calloc(len_m1, 1);
    m2 = checked_malloc(params->mu * sizeof (*m2));

    /* Generate S from sk */
    create_S(S_idx, sk, params);

    /* Unpack cipher text */
    unpack_ct(U_T, v, ct, len_u, params->p_bits, params->mu, params->t_bits);

#ifdef DEBUG
    uint16_t *U = checked_malloc(len_u * sizeof (*U));
    for (size_t i = 0; i < params->m_bar; ++i) {
        for (size_t j = 0; j < params->k; ++j) {
            for (size_t k = 0; k < params->n; ++k) {
                U[j * (size_t) (params->m_bar * params->n) + (size_t) (i * params->n) + k] = U_T[i * (size_t) (params->k * params->n) + (size_t) (j * params->n) + k];
            }
        }
    }
    print_sage_u_vector_matrix("r5_cpa_pke_decrypt: compressed U", U, params->k, params->m_bar, params->n);
    free(U);
    print_sage_u_vector("r5_cpa_pke_decrypt: compressed v", v, params->mu);
#endif

    /* Decompress v t_bits -> p_bits */
    decompress_matrix(v, params->mu, 1, params->t_bits, params->p_bits);

    /* X' = S_T * U */
    compute_STU(X_prime, U_T, S_idx, params);

#ifdef DEBUG
    for (size_t i = 0; i < params->mu; ++i) {
        X_prime[i] = (uint16_t) (X_prime[i] & (params->p - 1));
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: X'", X_prime, params->mu);
#endif

    /* v - X' */
    diff_msg(m2, params->mu, v, X_prime);

#ifdef DEBUG
    for (size_t i = 0; i < params->mu; ++i) {
        m2[i] = (uint16_t) (m2[i] & (params->p - 1));
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: uncompressed m2", m2, params->mu);
#endif

    /* Compress msg_tmp p_bits -> B */
    round_matrix(m2, params->mu, 1, params->p_bits, params->b_bits, params->h3);

#ifdef DEBUG
    for (size_t i = 0; i < params->mu; ++i) {
        m2[i] = (uint16_t) (m2[i] & ((1 << params->b_bits) - 1));
    }
    print_sage_u_vector("r5_cpa_pke_decrypt: m2", m2, params->mu);
#endif

    /* Convert the message to bit string format */
    pack(m1, m2, params->mu, params->b_bits);

#ifdef DEBUG
    print_hex("r5_cpa_pke_decrypt: m1", m1, len_m1, 1);
#endif

    if (params->xe != 0) {
        xef_compute(m1, params->kappa_bytes, params->f);
        xef_fixerr(m1, params->kappa_bytes, params->f);
    }
    memcpy(m, m1, params->kappa_bytes);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    print_hex("r5_cpa_pke_decrypt: m", m, params->kappa_bytes, 1);
#endif

    free(S_idx);
    free(U_T);
    free(v);
    free(X_prime);
    free(m2);
    free(m1);

    return 0;
}
