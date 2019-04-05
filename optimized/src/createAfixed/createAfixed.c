/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
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
