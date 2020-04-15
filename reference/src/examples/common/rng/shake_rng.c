/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Alternative implementation of the random bytes functions.
 *
 * Similar to the NIST rng implementation but uses shake256 to generate the
 * random bytes since that is faster.
 */

#include "rng.h"

#include <string.h>
#include "shake.h"

/*******************************************************************************
 * Private data
 ******************************************************************************/

/**
 * The RNG context data structure.
 */
typedef struct {
    shake_ctx shake_ctx; /**< The shake context */
    uint8_t buffer[SHAKE256_RATE]; /**< Buffer for output. */
    size_t index; /**< Current index in buffer. */
} rng_ctx;

/**
 * The context for the RNG.
 */
static rng_ctx ctx;

/*******************************************************************************
 * Public functions
 ******************************************************************************/

void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength) {
    unsigned char seed_material[48];
    (void) security_strength;

    memcpy(seed_material, entropy_input, 48);
    if (personalization_string) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= personalization_string[i];
        }
    }
    shake256_init(&ctx.shake_ctx);
    shake256_absorb(&ctx.shake_ctx, seed_material, 48);
    ctx.index = SHAKE256_RATE;
}

int randombytes(unsigned char *x, unsigned long long xlen) {
    size_t i, j;

    i = ctx.index;
    for (j = 0; j < xlen; j++) {
        if (i >= SHAKE256_RATE) {
            shake256_squeezeblocks(&ctx.shake_ctx, ctx.buffer, 1);
            i = 0;
        }
        x[j] = ctx.buffer[i++];
    }
    ctx.index = i;
    return 0;
}
