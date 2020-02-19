/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#include "matmul.h"


#if PARAMS_K !=1 && (defined(CM_CT) || defined(CM_CACHE))

#if !defined(AVX2)

#include "string.h"

// B = A * S

#if PARAMS_TAU == 0
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[PARAMS_D][PARAMS_D], tern_secret_s secret_vector) {
#elif PARAMS_TAU == 1
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D], tern_secret_s secret_vector) {
#else
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[PARAMS_TAU2_LEN + PARAMS_D], uint16_t a_permutation[PARAMS_D], tern_secret_s secret_vector) {
#endif
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_N_BAR * PARAMS_D * sizeof (modq_t));

#undef A_coeff
#if PARAMS_TAU == 0
#define A_coeff(j, i) a[j][i]
#else
#define A_coeff(j, i) a[a_permutation[j] + i]
#endif
    for (j = 0; j < PARAMS_D; j++) {
        for (l = 0; l < PARAMS_N_BAR; l++) {
            for (i = 0; i < PARAMS_D; i++) {
                d[j][l] = (modq_t) (d[j][l] + secret_vector[l][i] * A_coeff(j, i));
            }
        }
    }

#undef A_coeff
}

// U^T = R^T * A

#if PARAMS_TAU == 0
void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[PARAMS_D][PARAMS_D], tern_secret_r secret_vector) {
#elif PARAMS_TAU == 1
void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D], tern_secret_r secret_vector) {
#else
void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[PARAMS_TAU2_LEN + PARAMS_D], uint16_t a_permutation[PARAMS_D], tern_secret_r secret_vector) {
#endif
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_M_BAR * PARAMS_D * sizeof (modq_t));

#undef A_coeff
#if PARAMS_TAU == 0
#define A_coeff(i, j) a[i][j]
#else
#define A_coeff(i, j) a[a_permutation[i] + j]
#endif
    for (i = 0; i < PARAMS_D; i++) {
        for (j = 0; j < PARAMS_D; j++) {
            for (l = 0; l < PARAMS_M_BAR; l++) {
                d[l][j] = (modq_t) (d[l][j] + secret_vector[l][i] * A_coeff(i, j));
            }
        }
    }
#undef A_coeff
}

// X' = S^T * U

void matmul_stu_p(modp_t d[PARAMS_MU], modp_t u_t[PARAMS_M_BAR][PARAMS_D], tern_secret_s secret_vector) {
    size_t i, l, j;

    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));

    size_t index = 0;
    for (l = 0; l < PARAMS_N_BAR && index < PARAMS_MU; ++l) {
        for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; ++j) {
            for (i = 0; i < PARAMS_D; ++i) {
                d[index] = (modp_t) (d[index] + secret_vector[l][i] * u_t[j][i]);
            }
            ++index;
        }
    }
}


#endif /* !AVX2 */

// X = B^T * R

void matmul_btr_p(modp_t d[PARAMS_MU], modp_t b[PARAMS_D][PARAMS_N_BAR], tern_secret_r secret_vector) {
    size_t i, j, l;

    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));

    size_t index = 0;
    for (l = 0; l < PARAMS_N_BAR && index < PARAMS_MU; ++l) {
        for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; ++j) {
            for (i = 0; i < PARAMS_D; ++i) {
                d[index] = (modp_t) (d[index] + b[i][l] * secret_vector[j][i]);
            }
            ++index;
        }
    }
}

#endif /* PARAMS_K !=1 && (defined(CM_CT) || defined(CM_CACHE)) */
