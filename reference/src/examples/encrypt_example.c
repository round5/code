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
 * Example ENCRYPT application, shows the working of the algorithm.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#include "r5_cca_pke.h"
#include "misc.h"
#include "r5_memory.h"
#include "parameters.h"
#include "rng.h"
#include "a_fixed.h"

/**
 * Prints the parameters on `stdout`.
 *
 * @param[in] params the parameters
 */
static void print_parameters(const parameters *params) {
    printf("The chosen parameter set uses a ");
    if (params->k == 1) {
        printf("ring structure.");
        printf(" With");
        if (!params->xe) {
            printf("out");
        }
        printf(" error correction.\n");
    } else {
        printf("non-ring structure.\n");
    }
    printf("d          = %u\n", (unsigned) params->d);
    printf("n          = %u\n", (unsigned) params->n);
    printf("k          = %u\n", (unsigned) params->k);
    printf("h          = %u\n", (unsigned) params->h);
    printf("q          = %u\n", (unsigned) params->q);
    printf("p_bits     = %u\n", (unsigned) params->p_bits);
    printf("t_bits     = %u\n", (unsigned) params->t_bits);
    printf("n̅ (n_bar)  = %u\n", (unsigned) params->n_bar);
    printf("m̅ (m_bar)  = %u\n", (unsigned) params->m_bar);
    printf("b_bits)    = %u\n", (unsigned) params->b_bits);
    if (params->f) {
        printf("f          = %u\n", (unsigned) params->f);
        printf("xe         = %u\n", (unsigned) params->xe);
    }
    printf("mu         = %u\n", (unsigned) params->mu);
    printf("kappa      = %u\n", (unsigned) params->kappa);
    printf("sk_size    = %u\n", (unsigned) params->kappa_bytes);
    printf("pk_size    = %u\n", (unsigned) params->pk_size);
    printf("ct_size    = %u\n", (unsigned) params->ct_size);
    printf("tau        = %u\n", (unsigned) params->tau);
}

/**
 * Runs an example flow of the algorithm.
 *
 * @param[in] api_set_number the api set number to use, -1 for the ones set by
 *                           the NIST API macro definitions
 * @param[in] tau            the variant to use for the generation of A
 * @return __0__ in case of success
 */
static int example_run(int api_set_number, uint8_t tau) {
    parameters * params, non_api_params;
    unsigned long long ct_len, m_len;
    const char *message = "This is the message to be encrypted.";
    const unsigned long long message_len = strlen(message) + 1;
    /* Set up message containers */
    unsigned char *sk;
    unsigned char *pk;
    unsigned char *ct;
    unsigned char *m;

    /* Set up parameters */
    if (api_set_number < 0) {
        if ((params = set_parameters_from_api()) == NULL) {
            exit(1);
        }
        set_parameter_tau(params, tau); // Even when using the API values, we still allow setting tau
        printf("Using API parameters:\n");
        printf("CRYPTO_SECRETKEYBYTES =%u\n", CRYPTO_SECRETKEYBYTES);
        printf("CRYPTO_PUBLICKEYBYTES =%u\n", CRYPTO_PUBLICKEYBYTES);
        printf("CRYPTO_BYTES          =%u\n", CRYPTO_BYTES);
        printf("CRYPTO_CIPHERTEXTBYTES=%u\n", CRYPTO_CIPHERTEXTBYTES);
        printf("CRYPTO_ALGNAME        =%s\n", CRYPTO_ALGNAME);
        print_parameters(params);
        printf("This set of parameters correspond to NIST security level %c.\n", CRYPTO_ALGNAME[12]);
    } else {
        params = &non_api_params;
        set_parameters(params,
                tau,
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
                (uint8_t) r5_parameter_sets[api_set_number][POS_XE]);
        printf("Using api set %d parameters (Round5 %s)\n", api_set_number, r5_parameter_set_names[api_set_number]);
        print_parameters(params);
        printf("This set of parameters correspond to NIST security level %c.\n", r5_parameter_set_names[api_set_number][5]);
    }
    if (params->tau == 1) {
        unsigned char *seed = checked_malloc(params->kappa_bytes);
        randombytes(seed, params->kappa_bytes);
        print_hex("Generated A using seed", seed, params->kappa_bytes, 1);
        create_A_fixed(seed, params);
        free(seed);
    }
    printf("\n");

    /* Set up message containers */
    sk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
    pk = checked_malloc(get_crypto_public_key_bytes(params));
    m = checked_malloc(message_len);
    ct = checked_malloc((get_crypto_bytes(params, 1) + message_len));

    /* Initiator */
    printf("Initiator sets up key pair\n");
    r5_cca_pke_keygen_p(pk, sk, params);

    /* Initiator sends his pk */
    printf("Initiator sends his public key\n");

    /* Responder */
    printf("Responder encrypts message with public key and sends the cipher text\n");
    r5_cca_pke_encrypt_p(ct, &ct_len, (const unsigned char *) message, message_len, pk, params);

    /* Initiator */
    printf("Initiator decrypts cipher text with its secret key and determines the original message\n");
    r5_cca_pke_decrypt_p(m, &m_len, ct, ct_len, sk, params);

    printf("\n");
    printf("Comparing decrypted message with original: length=%s, message=%s\n", message_len != m_len ? "NOT OK" : "OK", message_len != m_len || memcmp(message, m, message_len) ? "NOT OK" : "OK");

    printf("\n");
    print_hex("Original Message ", (const unsigned char*) message, message_len, 1);
    print_hex("Decrypted Message", m, m_len, 1);

    free(sk);
    free(pk);
    free(ct);
    free(m);

    return 0;
}

/**
 * Main program, runs an example algorithm flow on a set of parameters as
 * specified either by the NIST API macros definitions or from the specified
 * api parameter set (from `api_to_internal_parameters.h`). The variant for
 * the creation of matric A (tau) can also be specified.
 *
 * @param argc the number of command-line arguments (including the executable itself)
 * @param argv the command-line arguments
 * @return __0__ in case of success
 */
int main(int argc, char **argv) {
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    int i;
    for (i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);

    long number;
    int ch;
    const long max_api_set_number = (long) (sizeof (r5_parameter_sets) / sizeof (r5_parameter_sets[0]));
    int api_set_number = 0;
    uint8_t tau = ROUND5_API_TAU;

    while ((ch = getopt(argc, argv, "a:t:")) != -1) {
        switch (ch) {
            case 'a':
                number = strtol(optarg, NULL, 10);
                if (number < -1 || number >= max_api_set_number) {
                    fprintf(stderr, "%s Invalid api set number specified: %s, must be less than %lu\n", argv[0], optarg, max_api_set_number);
                    exit(EXIT_FAILURE);
                }
                api_set_number = (int) number;
                break;
            case 't':
                number = strtol(optarg, NULL, 10);
                if (number < 0 || number > 2) {
                    fprintf(stderr, "%s Invalid tau specified: %s, must be 0, 1, or 2\n", argv[0], optarg);
                    exit(EXIT_FAILURE);
                }
                tau = (uint8_t) number;
                break;
            default:
                fprintf(stderr, "%s: unknown option %s\n", argv[0], optarg);
                exit(EXIT_FAILURE);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc > 0) {
        fprintf(stderr, "Usage: %s [-a N] [-t N]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    example_run(api_set_number, tau);
    return 0;
}
