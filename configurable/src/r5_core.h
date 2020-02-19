/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the core algorithm functions.
 */


#ifndef PST_CORE_H
#define PST_CORE_H

#include <stddef.h>

#include "chooseparameters.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Divides a polynomial in the NTRU ring by (X - 1), the result can
     * be taken to be in the cyclotomic ring.
     *
     * @param[out] cyc_pol   result
     * @param[in]  ntru_pol  polynomial in the NTRU ring
     * @param[in]  len       number of coefficients of the cyclotomic polynomial
     * @return __0__ in case of success
     */
    int unlift_poly(uint16_t *cyc_pol, const uint16_t *ntru_pol, size_t len);

    /**
     * Creates __A__ from the given parameters and seed.
     *
     * Note: in case of tau = 0 and tau = 2, the memory for A will be allocated.
     * In case of tau = 1, A_master is A_fixed
     *
     * @param[out] A_master       pointer to the created A_master
     * @param[in]  A_permutation  permutation of A_master
     * @param[in]  sigma          seed
     * @param[in]  params         the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_A(uint16_t **A_master, uint32_t *A_permutation, const unsigned char *sigma Parameters);

    /**
     * Creates random __S_idx__ from the given parameters.
     *
     * __S_idx__ has length _h * n_bar_.
     *
     * @param[out] S_idx   created _S_ in index form
     * @param[in]  sk      the secret key (used as seed)
     * @param[in]  params  the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_S(uint16_t *S_idx, const unsigned char *sk Parameters);

    /**
     * Creates random __R_idx__ from the given parameters.
     *
     * __R_idx__ has length _h * m_bar_.
     *
     * @param[out] R_idx    created _R_ in index form
     * @param[in]  rho      seed
     * @param[in]  params   the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_R(uint16_t *R_idx, const unsigned char *rho Parameters);

    /**
     * Decompress all coefficients in a matrix of polynomials from a bits to b bits.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a_bits compressed value number of bits
     * @param[in]  b_bits decompressed value number of bits
     * @return __0__ in case of success
     */
    int decompress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a_bits, const uint16_t b_bits);

    /**
     * Compress all coefficients in a matrix of polynomials from a bits to b bits,
     * rounding them down (with rounding constant added). Uses the
     * specified seed for generating the noise used for the rounding errors.
     *
     * @param[out] matrix            matrix to compress and compressed matrix
     * @param[in]  len               size of the matrix (rows * columns)
     * @param[in]  els               number of coefficients per polynomial
     * @param[in]  a                 original value bits
     * @param[in]  b                 compressed value bits
     * @param[in]  rounding_constant the constant for the rounding
     * @return __0__ in case of success
     */
    int round_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b, const uint16_t rounding_constant);

    /**
     * Computes __B__ as __A__*__S__ using the index form of S.
     *
     * @param[out] B             _B_
     * @param[in]  A_master      A_master
     * @param[in]  A_permutation permutation used to get A
     * @param[in]  S_idx         _S_ in index form
     * @param[in]  params        the algorithm parameters in use
     * @return __0__ in case of success
     */
    int compute_AS(uint16_t *B, const uint16_t *A_master, const uint32_t *A_permutation, const uint16_t *S_idx Parameters);

    /**
     * Computes __U^T__ where __U__ is __A^T__*__R__ (so __U^T__ is
     * __R^T__*__A__) using the index form of R.
     *
     * @param[out] U_T           __U^T__
     * @param[in]  A_master      __A_master__
     * @param[in]  A_permutation permutation used to get A
     * @param[in]  R_idx         __R__ in index form
     * @param[in]  params        the algorithm parameters in use
     * @return __0__ in case of success
     */
    int compute_RTA(uint16_t *U_T, const uint16_t *A_master, const uint32_t *A_permutation, const uint16_t *R_idx Parameters);

    /**
     * Computes mu values of __X__ with __X__ is __B^T__*__R__.
     *
     * @param[out] X                  _X_
     * @param[in]  B                  _B_
     * @param[in]  R_idx              _R_ in index form
     * @param[in]  params             the algorithm parameters in use
     * @return __0__ in case of success
     */
    int compute_BTR(uint16_t *X, uint16_t *B, const uint16_t *R_idx Parameters);

    /**
     * Computes mu values of __X'__ with ___X'__ is __S^T__*__U__.
     *
     * @param[out] X_prime            _X'_
     * @param[in]  U_T                _U^T_
     * @param[in]  S_idx              _S_ in index form
     * @param[in]  params             the algorithm parameters in use
     * @return __0__ in case of success
     */
    int compute_STU(uint16_t *X_prime, uint16_t *U_T, const uint16_t *S_idx Parameters);

#ifdef __cplusplus
}
#endif

#endif /* PST_CORE_H */
