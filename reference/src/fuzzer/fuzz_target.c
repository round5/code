/*
 * Copyright (c) 2019, Koninklijke Philips N.V.
 */

/**
 * @file
 * LibFuzzer and AFL target.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "misc.h"
#include "rng.h"
#include "r5_memory.h"
#include "chooseparameters.h"
#include "a_fixed.h"

#if CRYPTO_CIPHERTEXTBYTES == 0
#include "r5_cca_pke.h"
#else
#include "r5_cpa_kem.h"
#endif

#ifdef DOXYGEN
/** Macro to indicate the code is to be used for clang's libfuzzer. */
#define LIBFUZZER
#undef LIBFUZZER
/** Macro to indicate the fuzzer should run the responder-side. */
#define FUZZ_RESPONDER
#endif

/** The algorithm parameters in use */
    DeclareParameters;
    return (ssize_t) read_bytes;
}
#endif

/**
 * Runs a test flow of the algorithm.
 *
 * @param[in] Data input data, either CT (initiator test) or PK + message (responder test)
 * @param[in] Size size of input data
 * @return __0__
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#ifdef LIBFUZZER
    static int initialized = 0;
    if (!initialized) {
        /* Initialize random bytes */
        unsigned char entropy[48] = {0};
        randombytes_init(entropy, NULL, 256);
        initialized = 1;

        /* Set up parameters */
        if ((params = set_parameters_from_api()) == NULL) {
            exit(1);
        }
        if (PARAMS_TAU == 1 && PARAMS_N == 1) {
            unsigned char *seed = checked_malloc(PARAMS_KAPPA_BYTES);
            randombytes(seed, PARAMS_KAPPA_BYTES);
            create_A_fixed(seed Params);
            free(seed);
        }
    }
#endif

#ifdef FUZZ_RESPONDER
    if (Size < CRYPTO_PUBLICKEYBYTES) {
        return 0;
    }

#if CRYPTO_CIPHERTEXTBYTES == 0
    /* “Receive” PK, set up message */
    const unsigned char *pk = Data;
    const unsigned long long message_len = CRYPTO_PUBLICKEYBYTES < Size ? Size - CRYPTO_PUBLICKEYBYTES : 0;
    const unsigned char *message = message_len ? Data + CRYPTO_PUBLICKEYBYTES : NULL;
    unsigned char *ct = checked_malloc(CRYPTO_BYTES + message_len);
    unsigned long long ct_len;

    /* Responder encrypts message with public key and sends the cipher text */
    r5_cca_pke_encrypt(ct, &ct_len, message, message_len, pk Params);
#else
    /* “Receive” PK */
    const unsigned char *pk = Data;
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[CRYPTO_BYTES];

    /* Responder determines shared secret, encapsulates and sends the cipher text */
    r5_cpa_kem_encapsulate(ct, ss, pk Params);
#endif

#else /* !FUZZ_RESPONDER */

#if CRYPTO_CIPHERTEXTBYTES == 0
    if (Size < CRYPTO_BYTES) {
        return 0; /* To prevent messages known to be filtered by decrypt already */
    }
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    const unsigned long long message_len = CRYPTO_BYTES < Size ? Size - CRYPTO_BYTES : 0;
    unsigned char *m = checked_malloc(message_len);
    unsigned long long m_len;

    /* Initiator sets up key */
    r5_cca_pke_keygen(pk, sk Params);

    /* “Receive” CT */
    const unsigned char *ct = Data;
    unsigned long long ct_len = Size;

    /* Initiator decrypts cipher text with its secret key and determines the original message */
    r5_cca_pke_decrypt(m, &m_len, ct, ct_len, sk Params);

    free(m);
#else
    if (Size < CRYPTO_CIPHERTEXTBYTES) {
        return 0;
    }
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ss[CRYPTO_BYTES];

    /* Initiator sets up key */
    r5_cpa_kem_keygen(pk, sk Params);

    /* “Receive” CT */
    const unsigned char *ct = Data;

    /* Initiator de-encapsulates cipher text and determines shared secret */
    r5_cpa_kem_decapsulate(ss, ct, sk Params);
#endif

#endif /* LIBFUZZER */

    return 0;
}


#ifndef LIBFUZZER

/**
 * The program body. Reads data from stdin and runs the fuzzer test on it.
 *
 * @returns __0__ in case of success, __1__ in case of failure.
 */
int main(void) {
    /* Initialize random bytes */
    unsigned char entropy[48];
    randombytes_init(entropy, NULL, 256);

    /* Set up parameters */
    if ((params = set_parameters_from_api()) == NULL) {
        exit(1);
    }
    if (PARAMS_TAU == 1) {
        unsigned char *seed = checked_malloc(PARAMS_KAPPA_BYTES);
        randombytes(seed, PARAMS_KAPPA_BYTES);
        create_A_fixed(seed Params);
        free(seed);
    }

    unsigned char Data[100000];

    /* Run test on input data */
    ssize_t Size = read_bytes(Data, 100000, stdin);
    if (Size < 0) {
        fprintf(stderr, "Error reading stdin\n");
        exit(1);
    } else {
        LLVMFuzzerTestOneInput(Data, (size_t) Size);
    }
}
#endif
