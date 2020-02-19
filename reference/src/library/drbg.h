#ifndef _DRBG_H_
#define _DRBG_H_

/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the deterministic random bits (bytes) functions.
 */

/**
 * The default implementation of the DRBG uses (c)SHAKE for the generation of
 * the deterministic random bytes. This uses the official XKCP library. See
 * https://github.com/XKCP/XKCP
 * To make use of an stanalone implementation of (c)SHAKE, then define `STANDALONE`
 * or do `make STANDALONE=1`
 * To make use of the alternative AES (in CTR mode) implementation,
 * define `USE_AES_DRBG` or do `make USE_AES_DRBG=1`
 */

#endif

#define DRBG_SAMPLER16_INIT(range) \
    const uint32_t DRBG_SAMPLER16_range_divisor = (uint32_t) (0x10000 / range); \
    const uint32_t DRBG_SAMPLER16_range_limit = range * DRBG_SAMPLER16_range_divisor

#define DRBG_SAMPLER16(x) \
    do { \
         drbg_sampler16_2(x); \
    } while (x >= DRBG_SAMPLER16_range_limit); \
    x = (uint16_t) (x / DRBG_SAMPLER16_range_divisor)

#ifndef USE_AES_DRBG

#include "shaking.h"

// 	Exporting: Public interface

//	Types:

#define drbg_ctx Context

//	Exporting, Public interface

#define drbg_init(seed) \
	ContextInstance context = {0}; \
	r5_xof_input(&context, seed, PARAMS_KAPPA_BYTES Params) 

#define drbg(x, x_len) r5_xof_squeeze(&context, x, x_len Params)

#define drbg16(x, x_len) r5_xof_squeeze16(&context, x, x_len Params)

#define one_uint16_t(x) r5_xof_squeeze16(&context, &x, 1 Params)

#define drbg_sampler16_2_once(x, xlen, seed) \
	r5_xof16( x, xlen, (const uint8_t *) seed, PARAMS_KAPPA_BYTES Params )

// Customization

#define drbg_init_customization(seed, customization, customization_len) \
	CContextInstance context = {0}; \
	r5_xof_s_input(&context, seed, PARAMS_KAPPA_BYTES, customization, customization_len Params)

#define drbg_customization(x, xlen) r5_xof_s_squeeze(&context, x, xlen Params)

#define drbg16_customization(x, xlen) r5_xof_s_squeeze16(&context, x, xlen Params)

#define one_uint16_t_customization(x) r5_xof_s_squeeze16(&context, &x, 1 Params)

#define drbg_sampler16_2(x) r5_xof_s_squeeze16(&context, &x, 1 Params)

#define drbg_sampler16_2_reference(context, x) r5_xof_s_squeeze16(context, &x, 1 Params)

#define drbg_sampler16_2_once_customization(x, xlen, seed, c,c_len) \
	r5_xof_s16( x, xlen, seed, PARAMS_KAPPA_BYTES, c, c_len Params)

#define freeDRBGContext(context)

#else // using AES

#include "aesdrbg.h"

// 	Exporting: Public interface

//	Types:

#define drbg_ctx AESContext

//	Exporting, Public interface

#define drbg_init(seed) \
	initAESdrbg(context); \
	consume(&context, seed) 

#define drbg(x, x_len) produce(&context, x, x_len)

#define drbg16(x, x_len) produce16(&context, x, x_len)

#define one_uint16_t(x) produce16(&context, &x, 1)

#define one_uint16_t_reference(context, x) produce16(context, &x, 1)

#define drbg_sampler16_2_once(x, xlen, seed) \
	generate16( x, xlen, seed Params)

// Customization

#define drbg_init_customization(seed, customization, customization_len) \
	initAESdrbg(context); \
	cconsume(&context, seed, customization, customization_len Params)

#define drbg_customization(x, xlen) produce(&context, x, xlen)

#define drbg16_customization(x, xlen) produce16(&context, x, xlen)

#define one_uint16_t_customization(x) produce16(&context, &x, 1)

#define drbg_sampler16_2(x) produce16(&context, &x, 1)

#define drbg_sampler16_2_reference(context, x) produce16(context, &x, 1)

#define drbg_sampler16_2_once_customization(x, xlen, seed, c,c_len) \
	cgenerate16( x, xlen, seed, c, c_len Params)

#define freeDRBGContext(context) freeAESContext(context)

#endif /* _DRBG_H_ */

