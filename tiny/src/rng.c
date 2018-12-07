/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan
 *
 * All rights reserved. A copyright license for redistribution and use in
 * source and binary forms, with or without modification, is hereby granted for
 * non-commercial, experimental, research, public review and evaluation
 * purposes, provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * Implementation of the random bytes functions.
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
