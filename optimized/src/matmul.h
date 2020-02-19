/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#ifndef _MATMUL_H_
#define _MATMUL_H_

#include "r5_parameter_sets.h"

#if PARAMS_K != 1

//#if !defined(CM_CT) || !defined(CM_CACHE)
//void create_secret_matrix_s_t(tern_secret_s secret_vector, const uint8_t *seed);
//void create_secret_matrix_r_t(tern_secret_r secret_vector, const uint8_t *seed);
//#endif

#if PARAMS_TAU == 0
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[PARAMS_D][PARAMS_D], tern_secret_s secret_vector);
void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[PARAMS_D][PARAMS_D], tern_secret_r secret_vector);
#elif PARAMS_TAU == 1
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D], tern_secret_s secret_vector);
void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D], tern_secret_r secret_vector);
#else
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t a[PARAMS_TAU2_LEN + PARAMS_D], uint16_t a_permutation[PARAMS_D], tern_secret_s secret_vector);
void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t a[PARAMS_TAU2_LEN + PARAMS_D], uint16_t a_permutation[PARAMS_D], tern_secret_r secret_vector);
#endif

void matmul_stu_p(modp_t d[PARAMS_MU], modp_t u_t[PARAMS_M_BAR][PARAMS_D], tern_secret_s secret_vector);

void matmul_btr_p(modp_t d[PARAMS_MU], modp_t b[PARAMS_D][PARAMS_N_BAR], tern_secret_r secret_vector);

#endif /* PARAMS_K != 1 */

#endif /* _MATMUL_H_ */
