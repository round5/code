/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Speed tests for the Round5 reference and optimized implementations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "cpa_kem.h"
#include "cca_encrypt.h"
#include "parameters.h"
#include "test_utils.h"
#include "misc.h"
#include "rng.h"

#if CRYPTO_CIPHERTEXTBYTES != 0
/**
 * Runs the speed tests for the individual steps of the KEM algorithm.
 *
 * @param[in] nr_test_repeats the number of times the tests should be repeated
 * @return __0__ on success, __1__ on failure
 */
static unsigned int speedtest(const unsigned int nr_test_repeats) {
    unsigned int i, subtest;
    unsigned int nr_failed = 0;
    const char *subtest_names[] = {
        "crypto_kem_keypair",
        "crypto_kem_enc",
        "crypto_kem_dec",
    };
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss_r[CRYPTO_BYTES];
    unsigned char ss_i[CRYPTO_BYTES];
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];

    start_speed_test_suite("speed_tests", subtest_names, 3, nr_test_repeats);

    for (i = 0; i < nr_test_repeats; ++i) {
        subtest = 0;

        /* Setup key pairs */
        TIME_TEST_REPEAT(subtest++, i, crypto_kem_keypair(pk, sk));

        /* Encode  */
        TIME_TEST_REPEAT(subtest++, i, crypto_kem_enc(ct, ss_r, pk));

        /* Decode */
        TIME_TEST_REPEAT(subtest++, i, crypto_kem_dec(ss_i, ct, sk));

        if (memcmp(ss_r, ss_i, CRYPTO_BYTES)) {
            ++nr_failed;
            fprintf(stderr, "Failed test %u\n", i);
        }
    }

    if (nr_failed) {
        fprintf(stderr, "Failed %u times (%u%%)\n", nr_failed, 100 * nr_failed / nr_test_repeats);
    }

    end_speed_test_suite("Complete Round5.KEM");

    return nr_failed != 0;
}

#else

/**
 * Runs the speed tests for the individual steps of the PKE algorithm.
 *
 * @param[in] nr_test_repeats the number of times the tests should be repeated
 * @return __0__ on success, __1__ on failure
 */
static unsigned int speedtest(const unsigned int nr_test_repeats) {
    unsigned int i, subtest;
    unsigned int nr_failed = 0;
    const char *subtest_names[] = {
        "crypto_encrypt_keypair",
        "crypto_encrypt",
        "crypto_encrypt_open",
    };
    const char *message = "This is the message to be encrypted.";
    const unsigned long long message_len = strlen(message) + 1;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char *ct = malloc(CRYPTO_BYTES + message_len);
    unsigned char *m = malloc(message_len);
    unsigned long long clen;
    unsigned long long mlen;

    memset(ct, 0, CRYPTO_BYTES + message_len);
    memset(m, 0, message_len);

    start_speed_test_suite("speed_tests", subtest_names, 3, nr_test_repeats);

    for (i = 0; i < nr_test_repeats; ++i) {
        subtest = 0;

        /* Setup key pairs */
        TIME_TEST_REPEAT(subtest++, i, crypto_encrypt_keypair(pk, sk));

        /* Encode  */
        TIME_TEST_REPEAT(subtest++, i, crypto_encrypt(ct, &clen, (const unsigned char *) message, message_len, pk));

        /* Decode */
        TIME_TEST_REPEAT(subtest++, i, crypto_encrypt_open(m, &mlen, ct, clen, sk));

        if (message_len != mlen || memcmp(message, m, message_len)) {
            ++nr_failed;
            fprintf(stderr, "Failed test %u\n", i);
        }
    }

    if (nr_failed) {
        fprintf(stderr, "Failed %u times (%u%%)\n", nr_failed, 100 * nr_failed / nr_test_repeats);
    }

    end_speed_test_suite("Complete Round5.PKE");

    return nr_failed != 0;
}

#endif

/**
 * Prints a usage message on `stderr` and exits the program.
 *
 * @param[in] message additional message to show (`NULL` for no message)
 */
static void usage(const char *message) {
    if (message != NULL) {
        fprintf(stderr, "%s\n", message);
    }
    fprintf(stderr, "Usage: speedtest [-r <repeats>]\n");
    exit(EXIT_FAILURE);
}

/**
 * Runs the speed tests.
 *
 * @param[in] argc the number of command-line arguments
 * @param[in] argv the command-line arguments
 * @return __0__ if the tests were run successfully, __1__ otherwise
 */
int main(int argc, char** argv) {
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    int i;
    for (i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);

    long number;
    int ch;
    unsigned int nr_failed = 0;

    unsigned int nr_test_repeats = 100;

    while ((ch = getopt(argc, argv, "?r:")) != -1) {
        switch (ch) {
            case 'r':
                number = strtol(optarg, NULL, 10);
                if (number <= 0) {
                    usage("Invalid number of test repeats specified");
                }
                nr_test_repeats = (unsigned int) number;
                break;
            default:
                usage(NULL);
        }
    }
    argc -= optind;
    argv += optind;
    if (argc > 0)
        usage(NULL);

#ifdef USE_AES_DRBG
#define AES_TXT "AES "
#else
#define AES_TXT "----"
#endif
    printf("----- Configuration %s T%d %s%.*s\n\n", CRYPTO_ALGNAME, ROUND5_API_TAU, AES_TXT, (int) (80 - 28 - strlen(CRYPTO_ALGNAME)), "---------------------------------------------");

    printf("CRYPTO_SECRETKEYBYTES  = %u\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_PUBLICKEYBYTES  = %u\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_BYTES           = %u\n", CRYPTO_BYTES);
    if (CRYPTO_CIPHERTEXTBYTES != 0) {
        printf("CRYPTO_CIPHERTEXTBYTES = %u\n", CRYPTO_CIPHERTEXTBYTES);
    }
    printf("Tests are repeated %u times\n\n", nr_test_repeats);

    return speedtest(nr_test_repeats) ? EXIT_FAILURE : EXIT_SUCCESS;
}
