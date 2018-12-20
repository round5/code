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
 * Application to generate an A_fixed matrix using the parameters as set.
 * The output of the application can be used to set up the fixed A matrix in
 * the file `a_fixed.h`.
 */

#include "r5_parameter_sets.h"
#include "rng.h"
#include "drbg.h"
#include "misc.h"
#include "a_fixed.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Outputs the definition of a fixed A matrix based on the API parameter as set.
 *
 * @return __0__ in case of success
 */
int main(void) {
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    int i;
    for (i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);

    unsigned char seed[PARAMS_KAPPA_BYTES];
    randombytes(seed, PARAMS_KAPPA_BYTES);
    create_A_fixed(seed);

    printf("/* A_fixed for %s */\n\n", CRYPTO_ALGNAME);
    printf("/* Seed used for the generation of A_fixed: ");
    print_hex(NULL, seed, PARAMS_KAPPA_BYTES, 1);
    printf(" */\n");
    printf("modq_t A_fixed[PARAMS_D * 2 * PARAMS_K] = {\n");
    for (int i = 0; i < 2 * PARAMS_K; ++i) {
        if (i > 0) {
            printf(",\n");
        }
        printf("  ");
        for (int j = 0; j < PARAMS_D; ++j) {
            if (j > 0) {
                if (j % 16 == 0) {
                    printf(",\n    ");
                } else {
                    printf(", ");
                }
            }
            printf("%u", A_fixed[i * PARAMS_D + j] & (PARAMS_Q - 1));
        }
    }
    printf("\n};\n");

    return 0;
}
