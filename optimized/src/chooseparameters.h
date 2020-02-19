/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#define PARAMETERCONSTANT

#define SHAKE128_RATE 168
// 168 bytes as a bytesequence = 1344 bits as a bitsequence

#define SHAKE256_RATE 136
// 136 bytes as a bytesequence = 1088 bits as a bitsequence

#ifdef PARAMETERCONSTANT

#include "r5_parameter_sets.h"

#define Parameters  
#define Params 
#define useParams 

#if (PARAMS_KAPPA_BYTES > 16)
#define RATE SHAKE256_RATE
#else
#define RATE SHAKE128_RATE
#endif

#define DeclareParameters

#else

#include "parameters.h"

#define Parameters , const parameters * params
#define Params , params
#define useParams params = params ;

#define DeclareParameters\
    parameters * params; \
    if ((params = set_parameters_from_api()) == NULL) \
        exit(EXIT_FAILURE)


#define RATE (params->kappa_bytes > 16 ? SHAKE256_RATE : SHAKE128_RATE )
#define PARAMS_B_BITS (params->b_bits)
#define PARAMS_T_BITS (params->t_bits)
#define PARAMS_P_BITS (params->p_bits)
#define PARAMS_Q_BITS (params->q_bits)
#define PARAMS_CT_SIZE (params->ct_size)
#define PARAMS_PK_SIZE (params->pk_size)
#define PARAMS_D (params->d)
#define PARAMS_Q (params->q)
#define PARAMS_H (params->h)
#define PARAMS_H1 (params->h1)
#define PARAMS_H2 (params->h2)
#define PARAMS_H3 (params->h3)
#define PARAMS_F (params->f)
#define PARAMS_K (params->k)
#define PARAMS_N (params->n)
#define PARAMS_N_BAR (params->n_bar)
#define PARAMS_M (params->m)
#define PARAMS_MU (params->mu)
#define PARAMS_M_BAR (params->m_bar)
#define PARAMS_P (params->p)
#define PARAMS_TAU (params->tau)
#define PARAMS_TAU2_LEN (params->tau2_len)
#define PARAMS_KAPPA (params->kappa)
#define PARAMS_KAPPA_BYTES (params->kappa_bytes)
#define PARAMS_CT_SIZE (params->ct_size)
#define PARAMS_XE (params->xe)

#endif

