/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Application to generate an A_fixed matrix using the parameters from the
 * API parameter set as specified on the command-line. The output of the
 * application can be used to set up the fixed A  matrix in the file
 * `a_fixed.h` e.g. when using the NIST API versions of the algorithm
 * interface.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#include "parameters.h"
#include "rng.h"
#include "drbg.h"
#include "misc.h"
#include "r5_memory.h"
#include "a_fixed.h"

/**
 * Outputs the definition of a fixed A matrix based on the API parameter set as
 * specified on the command-line.
 *
 * @param argc the number of command-line arguments (including the executable itself)
 * @param argv the command-line arguments
 * @return __0__ in case of success
 */
int main(int argc, char **argv) {
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    size_t i;
    for (i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);

    parameters params;
    unsigned char *seed;
    size_t j;

    unsigned long api_set_number = 0;

    if (argc > 1) {
        api_set_number = (unsigned long) strtol(argv[1], NULL, 10);
    }

    if (api_set_number > sizeof (r5_parameter_sets) / sizeof (r5_parameter_sets[0])) {
        fprintf(stderr, "%s: invalid api set number specified (%s), must be less than %lu\n", argv[0], argv[1], sizeof (r5_parameter_sets) / sizeof (r5_parameter_sets[0]));
        exit(EXIT_FAILURE);
    }

    if (r5_parameter_sets[api_set_number][POS_N] != 1) {
        fprintf(stderr, "%s: invalid api set number specified (%s), must be a Non-Ring parameter set\n", argv[0], argv[1]);
        exit(EXIT_FAILURE);
    }

    /* Set up */
    if (set_parameters(&params,
            1,
            0,
            (uint8_t) r5_parameter_sets[api_set_number][POS_KAPPA_BYTES],
            (uint16_t) r5_parameter_sets[api_set_number][POS_D],
            (uint16_t) r5_parameter_sets[api_set_number][POS_N],
            (uint16_t) r5_parameter_sets[api_set_number][POS_H],
            (uint8_t) r5_parameter_sets[api_set_number][POS_Q_BITS],
            (uint8_t) r5_parameter_sets[api_set_number][POS_P_BITS],
            (uint8_t) r5_parameter_sets[api_set_number][POS_T_BITS],
            (uint8_t) r5_parameter_sets[api_set_number][POS_B_BITS],
            (uint16_t) r5_parameter_sets[api_set_number][POS_N_BAR],
            (uint16_t) r5_parameter_sets[api_set_number][POS_M_BAR],
            (uint8_t) r5_parameter_sets[api_set_number][POS_F],
            (uint8_t) r5_parameter_sets[api_set_number][POS_XE])) {
        fprintf(stderr, "%s: Invalid parameters\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialise drbg */
    seed = checked_malloc(params.kappa_bytes);
    randombytes(seed, params.kappa_bytes);

    create_A_fixed(seed, &params);

    /* Print A_fixed */
    printf("/* Seed used for the generation of A_fixed: ");
    print_hex(NULL, seed, params.kappa_bytes, 1);
    printf(" */\n");
    printf("size_t A_fixed_len = %u;\n", params.k * params.d);
    printf("uint16_t *A_fixed = (uint16_t[%u]){\n", params.k * params.d);
    for (i = 0; i < params.k; ++i) {
        if (i > 0) {
            printf(",\n");
        }
        printf("    ");
        for (j = 0; j < params.d; ++j) {
            if (j > 0) {
                if (j % 16 == 0) {
                    printf(",\n    ");
                } else {
                    printf(", ");
                }
            }
            printf("%hu", A_fixed[i * params.d + j]);
        }
    }
    printf("\n};\n");

    return 0;
}
