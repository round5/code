#ifndef _DRBG_H_
#define _DRBG_H_

/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of functions used to obtain a deterministic sequence of pseudorandom data given a seed of true random data.
 */

/**
 * The default implementation uses TupleHash(XOF) using the XKCP library.
 * See https://github.com/XKCP/XKCP.
 * Alternatively, it is possible to use an standalone implementation of TupleHash(XOF) by defining `STANDALONE`.
 * Finally, by doing `make AES=1z, the generation of A uses AES in counter mode.
 */

#endif

#include "f202sp800185.h"


/************ Secret key generation Generation ***********************/

#define SKGenerationInit(d, i1, i2) \
ttupleHash_Instance thcontext = {0}; \
uint32_t i2len = 1; \
r5_tuple_hash_input(&thcontext, d, 4, i1, PARAMS_KAPPA_BYTES, i2, i2len, 3, 0 Params)

#define SKGenerationGen(o, olen) \
r5_tuple_hash_xof_squeeze16(o, olen, &thcontext Params)

#define SKGenerationInit_4x(d, i1, i20, i21, i22, i23) \
ttupleHash_Instance thcontext = {0}; \
uint32_t i2len = 1; \
r5_tuple_hash_input_4x(&thcontext, d, d, d, d, 4, i1, i1, i1, i1, PARAMS_KAPPA_BYTES, i20, i21, i22, i23, i2len, 3, 0 Params)

#define SKGenerationGen_4x(o0, o1, o2, o3, olen) \
r5_tuple_hash_xof_squeeze16_4x(o0, o1, o2, o3, olen, &thcontext Params)


/************ Permutation Generation ***********************/

#define APermutationInit(i1, olen) \
    ttupleHash_Instance thcontext = {0}; \
    const uint8_t d[12] = "APermutation"; \
    r5_tuple_hash_input(&thcontext, d, 12, i1, PARAMS_KAPPA_BYTES, NULL, 0, 2, 0 Params)

#define APermutationGen(o, olen) \
    r5_tuple_hash_xof_squeeze16(o, olen, &thcontext Params)

/************ A Generation ***********************/

#if (defined(AVX2))  && (defined(STANDALONE))

#define AGeneration4x(o0, o1, o2, o3, olen, d, i1, i20, i21, i22, i23) \
    r5_tuple_hash16_4x(o0, o1, o2, o3, olen, d, d, d, d, 4, i1, i1, i1, i1, PARAMS_KAPPA_BYTES, i20, i21, i22, i23, 1, 3 Params)

#else

#if (!defined(USE_AES_DRBG))

#define AGeneration(o, olen, d, i1, i2) \
    r5_tuple_hash16(o, olen, d, 4, i1, PARAMS_KAPPA_BYTES, i2, 1, 3 Params)

#else // AGeneration using AES in counter mode

#include "aesdrbg.h"
#define AGeneration(o, olen, d, i1, i2) \
    aesctr16(o, olen, d, 4, i1, PARAMS_KAPPA_BYTES, i2, 1 Params)

#endif
#endif



