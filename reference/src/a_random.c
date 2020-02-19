/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the random A matrix creation function.
 */

#include "a_random.h"

#include "misc.h"
#include "little_endian.h"
#include "drbg.h"

int create_A_random(uint16_t *A_random, const unsigned char *seed Parameters) {
    if (PARAMS_TAU == 2) {
        drbg_sampler16_2_once(A_random, PARAMS_TAU2_LEN, seed);
    } else {
        drbg_sampler16_2_once(A_random, (size_t) (PARAMS_D * PARAMS_K), seed);
    }
	return 0;
}
