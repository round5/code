/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Example PKE application, shows the working of the algorithm.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>

#include "chooseparameters.h"
#include "r5_cca_pke.h"
#include "misc.h"
#include "r5_memory.h"
#include "rng.h"
#include "a_fixed.h"

/**
 * Prints the parameters on `stdout`.
 *
 * @param[in] params the parameters
 */
static void print_parameters(const parameters *params) {
    printf("The chosen parameter set uses a ");
    if (PARAMS_K == 1) {
        printf("ring structure.");
        printf(" With");
        if (!PARAMS_XE) {
            printf("out");
        }
        printf(" error correction.\n");
    } else {
        printf("non-ring structure.\n");
    }
    printf("d          = %u\n", (unsigned) PARAMS_D);
    printf("n          = %u\n", (unsigned) PARAMS_N);
    printf("k          = %u\n", (unsigned) PARAMS_K);
    printf("h          = %u\n", (unsigned) PARAMS_H);
    printf("q          = %u\n", (unsigned) PARAMS_Q);
    printf("p_bits     = %u\n", (unsigned) PARAMS_P_BITS);
    printf("t_bits     = %u\n", (unsigned) PARAMS_T_BITS);
    printf("b_bits     = %u\n", (unsigned) PARAMS_B_BITS);
    printf("n̅ (n_bar)  = %u\n", (unsigned) PARAMS_N_BAR);
    printf("m̅ (m_bar)  = %u\n", (unsigned) PARAMS_M_BAR);
    if (PARAMS_F) {
        printf("f          = %u\n", (unsigned) PARAMS_F);
        printf("xe         = %u\n", (unsigned) PARAMS_XE);
    }
    printf("mu         = %u\n", (unsigned) PARAMS_MU);
    printf("kappa      = %u\n", (unsigned) PARAMS_KAPPA);
    printf("sk_size    = %u\n", (unsigned) PARAMS_KAPPA_BYTES);
    printf("pk_size    = %u\n", (unsigned) PARAMS_PK_SIZE);
    printf("ct_size    = %u\n", (unsigned) PARAMS_CT_SIZE);
    printf("tau        = %u\n", (unsigned) PARAMS_TAU);
    if (PARAMS_TAU == 2) {
        printf("tau2_len   = %u\n", (unsigned) PARAMS_TAU2_LEN);
    }
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
    int is_cca = 0;
    int ok = 0;
    parameters * params, non_api_params;

    /* Set up parameters */
    if (api_set_number < 0) {
        if ((params = set_parameters_from_api()) == NULL) {
            fprintf(stderr, "example: Invalid parameters\n");
            exit(EXIT_FAILURE);
        }
        set_parameter_tau(params, tau); // Even when using the API values, we still allow setting tau
        printf("Using API parameters:\n");
        printf("CRYPTO_SECRETKEYBYTES =%u\n", CRYPTO_SECRETKEYBYTES);
        printf("CRYPTO_PUBLICKEYBYTES =%u\n", CRYPTO_PUBLICKEYBYTES);
        printf("CRYPTO_BYTES          =%u\n", CRYPTO_BYTES);
        printf("CRYPTO_CIPHERTEXTBYTES=%u\n", CRYPTO_CIPHERTEXTBYTES);
        printf("CRYPTO_ALGNAME        =%s\n", CRYPTO_ALGNAME);
        print_parameters(params);
        printf("This set of parameters correspond to NIST security level %c.\n", CRYPTO_ALGNAME[5]);
        is_cca = CRYPTO_CIPHERTEXTBYTES == 0;
    } else {
        params = &non_api_params;
        if (set_parameters(params,
                tau,
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
            fprintf(stderr, "example: Invalid parameters\n");
            exit(EXIT_FAILURE);
        }

        printf("Using api set %d parameters (Round5 %s)\n", api_set_number, r5_parameter_set_names[api_set_number]);
        print_parameters(params);
        printf("This set of parameters correspond to NIST security level %c.\n", r5_parameter_set_names[api_set_number][5]);
        is_cca = r5_parameter_sets[api_set_number][API_CIPHER] == 0;
    }
    if (PARAMS_TAU == 1) {
        unsigned char *seed = checked_malloc(PARAMS_KAPPA_BYTES);
        randombytes(seed, PARAMS_KAPPA_BYTES);
        print_hex("Generated A using seed", seed, PARAMS_KAPPA_BYTES, 1);
        create_A_fixed(seed Params);
        free(seed);
    }
    printf("\n");

    if (is_cca) {
 
        unsigned long long ct_len, m_len;
        const char *message = "This is the message to be encrypted.";
        const unsigned long long message_len = strlen(message) + 1;

        /* Set up message containers */
        unsigned char *sk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
        unsigned char *pk = checked_malloc(get_crypto_public_key_bytes(params));
        unsigned char *m = checked_malloc(message_len);
        unsigned char *ct = checked_malloc((get_crypto_bytes(params, 1) + message_len));

        /* Initiator */
        printf("Initiator sets up key pair\n");
        r5_cca_pke_keygen(pk, sk Params);

        /* Initiator sends his pk */
        printf("Initiator sends his public key\n");

        /* Responder */
        printf("Responder encrypts message with public key and sends the cipher text\n");
        r5_cca_pke_encrypt(ct, &ct_len, (const unsigned char *) message, message_len, pk Params);

        /* Initiator */
        printf("Initiator decrypts cipher text with its secret key and determines the original message\n");
        r5_cca_pke_decrypt(m, &m_len, ct, ct_len, sk Params);

        printf("\n");
        printf("Comparing decrypted message with original: length=%s, message=%s\n", message_len != m_len ? "NOT OK" : "OK", message_len != m_len || memcmp(message, m, message_len) ? "NOT OK" : "OK");
        ok = message_len != m_len || memcmp(message, m, message_len);

        printf("\n");
        print_hex("Original Message ", (const unsigned char*) message, message_len, 1);
        print_hex("Decrypted Message", m, m_len, 1);

        free(sk);
        free(pk);
        free(ct);
        free(m);
    } else {
        
        printf("This parameter set is not suitable for PKE.\n");
       
    }

    return ok;
}

/**
 * Main program, runs an example algorithm flow on a set of parameters as
 * specified either by the NIST API macros definitions or from the specified
 * api parameter set (from `r5_parameter_sets`). The variant for
 * the creation of matrix A (tau) can also be specified.
 *
 * @param argc the number of command-line arguments (including the executable itself)
 * @param argv the command-line arguments
 * @return __0__ in case of success
 */
int main(int argc, char **argv) {
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);

    int ch;
    long number;
    const long max_api_set_number = (long) (sizeof (r5_parameter_set_names) / sizeof (r5_parameter_set_names[0]));
    int api_set_number = -1;
    uint8_t tau = ROUND5_API_TAU;

    while ((ch = getopt(argc, argv, "a:t:")) != -1) {
        switch (ch) {
            case 'a':
                do {
                    ++api_set_number;
                } while (api_set_number < max_api_set_number && strcmp(r5_parameter_set_names[api_set_number], optarg));
                if (api_set_number >= max_api_set_number) {
                    fprintf(stderr, "%s Invalid api set name \"%s\" specified, must be one of:", argv[0], optarg);
                    for (long i = 0; i < max_api_set_number; ++i) {
                        if (i) {
                            printf(",");
                        }
                        printf(" %s", r5_parameter_set_names[i]);
                    }
                    printf("\n");
                    exit(EXIT_FAILURE);
                }
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
        fprintf(stderr, "Usage: %s [-a <PARAMETER_SET_NAME>] [-t N]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    return example_run(api_set_number, tau);
}


