#ifndef _R5_HASH_H_
#define _R5_HASH_H_

/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Definition of the hash function as used within Round5.
 */

#include "shaking.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * The hash function as used within Round5.
     *
     * @param[out] output            buffer for the output of the hash
     * @param[in]  output_len        the number of hash bytes to produce
     * @param[in]  input             the input to produce the hash for
     * @param[in]  input_len         the number of input bytes
     * @param[in]  customization     the customization string to use
     * @param[in]  customization_len the length of the customization string
     * @param Parameters            the number of bytes of kappa (used to
     *                               determine the the implementation of the
     */    

inline void hash
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters )
{ r5_xof(output, outputLength, input, inputLength Params); }

    /**
     * The hash function as used within Round5.
     *
     * @param[out] output      buffer for the output of the hash
     * @param[in]  output_len  the number of hash bytes to produce
     * @param[in]  input       the input to produce the hash for
     * @param[in]  input_len   the number of input bytes
     * @param[in]  Parameters  bytes of kappa (used to determine
     *                         the implementation of the hash function)
     */

inline void hash_customization 
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters )
{ r5_xof_s(output, outputLength, input, inputLength, customization, customizationLength Params); }

#ifdef __cplusplus
}
#endif

#endif /* _R5_HASH_H_ */
