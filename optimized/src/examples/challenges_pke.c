/*
 * Copyright (c) 2019, Koninklijke Philips N.V.
 */

/**
 * @file
 * Application to compute Round5 PKE challenges.
 */

#include <stdio.h>
#include "pke.h"

#ifdef ROUND5_CCA_PKE

#include "rng.h"
#include "r5_memory.h"

#include <stdlib.h>
#include <string.h>

#if PARAMS_TAU == 1 && PARAMS_N == 1
#include "a_fixed.h"
#endif

/**
 * Prints the parameters on `stdout`.
 */
static void print_parameters() {
    printf("The chosen parameter set uses a ");
    if (PARAMS_N == PARAMS_D) {
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

#if CHALLENGE
static void print_to_file(FILE *f, const char *name, const unsigned char *data, const size_t nr_elements) {
    fprintf(f, "%s: [", name);
    for (int c = 0 ; c< nr_elements; c++ ){
        fprintf(f, "%d ", data[c]);
    }
    fprintf(f, "]\n");
}
#endif

/**
 * Runs an example flow of the algorithm.
 *
 * @return __0__ in case of success
 */
static int example_run() {

#if CHALLENGE
    FILE *f_challenge, *f_challenge_and_sk;
#endif
    
    int ok = 0;
    int num_runs = 1;
    
    printf("Using API parameters:\n");
    printf("CRYPTO_SECRETKEYBYTES =%u\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_PUBLICKEYBYTES =%u\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_BYTES          =%u\n", CRYPTO_BYTES);
    printf("CRYPTO_CIPHERTEXTBYTES=%u\n", CRYPTO_CIPHERTEXTBYTES);
    printf("CRYPTO_ALGNAME        =%s\n", CRYPTO_ALGNAME);
    print_parameters();
    printf("This set of parameters correspond to NIST security level %c.\n", CRYPTO_ALGNAME[5]);

#if CHALLENGE
    #if PARAMS_TAU == 0
    char tau[5] = "_tau0";
    #endif
    #if PARAMS_TAU == 1
    char tau[5] = "_tau1";
    #endif
    #if PARAMS_TAU == 2
    char tau[5] = "_tau2";
    #endif
    
    char name[1024] = "pk_ct_";
    strcat( name, CRYPTO_ALGNAME);
    strcat( name, tau);
    strcat( name, ".txt");
    f_challenge = fopen(name, "w");

    char name2[1024] = "sk_";
    strcat( name2, CRYPTO_ALGNAME);
    strcat( name2, tau);
    strcat( name2, ".txt");
    f_challenge_and_sk = fopen(name2, "w");
    
    num_runs = 100;
    
    fprintf(f_challenge, "See definitions of pk and ct in Algorithms 22, 23, 24 at https://round5.org/Supporting_Documentation/Round5_Submission.pdf \n\n");
    
#endif
    
    
#if PARAMS_TAU == 1 && PARAMS_N == 1
    unsigned char seed[PARAMS_KAPPA_BYTES];
    randombytes(seed, PARAMS_KAPPA_BYTES);
    print_hex("Generated A using seed", seed, PARAMS_KAPPA_BYTES, 1);
    create_A_fixed(seed);
#if CHALLENGE == 1
    print_to_file(f_challenge, "Seed to generate A_{master}", seed, PARAMS_KAPPA_BYTES);
#endif
#endif
    printf("\n");

    
    
    
    for (int challenge = 0 ; challenge < num_runs ; challenge++){
    
    
        
        unsigned long long ct_len, mlen;
        const char *message = "This is the message to be encrypted.";
        const unsigned long long message_len = strlen(message) + 1;

        /* Set up message containers */
        unsigned char sk[CRYPTO_SECRETKEYBYTES];
        unsigned char pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char *m;
        unsigned char *ct;
        m = checked_malloc(message_len);
        ct = checked_malloc((size_t) (CRYPTO_BYTES + message_len));

        /* Initiator */
        printf("Initiator sets up key pair\n");
        crypto_encrypt_keypair(pk, sk);
        
    #if CHALLENGE == 1
        fprintf(f_challenge, "\nChallenge #%i \n", challenge);
        print_to_file(f_challenge, "pk", pk, CRYPTO_PUBLICKEYBYTES);
        
        fprintf(f_challenge_and_sk, "Challenge #%i \n", challenge);
        print_to_file(f_challenge_and_sk, "sk", sk, CRYPTO_SECRETKEYBYTES);
    #endif

        
        /* Initiator sends his pk */
        printf("Initiator sends his public key\n");

        /* Responder */
        printf("Responder encrypts message with public key and sends the cipher text\n");
        crypto_encrypt(ct, &ct_len, (const unsigned char *) message, message_len, pk);

    #if CHALLENGE == 1
            print_to_file(f_challenge, "ct", ct, ct_len);
    #endif
   
        /* Initiator */
        printf("Initiator decrypts cipher text with its secret key and determines the original message\n");
        crypto_encrypt_open(m, &mlen, ct, ct_len, sk);

        printf("\n");
        printf("Comparing decrypted message with original: length=%s, message=%s\n", message_len != mlen ? "NOT OK" : "OK", message_len != mlen || memcmp(message, m, message_len) ? "NOT OK" : "OK");
        ok = message_len != mlen || memcmp(message, m, message_len);

        printf("\n");
        print_hex("Original Message ", (const unsigned char*) message, message_len, 1);
        print_hex("Decrypted Message", m, mlen, 1);

        free(ct);
        free(m);
    
    }
    
#if CHALLENGE
    fclose(f_challenge);
    fclose(f_challenge_and_sk);
    if (ok != 0){
        f_challenge = fopen(name, "w");
        f_challenge_and_sk = fopen(name2, "w");
        
        fclose(f_challenge);
        fclose(f_challenge_and_sk);
    }
#endif
    
    return ok;
}

#endif

/**
 * Main program, runs an example algorithm flow.
 *
 * @return __0__ in case of success
 */
int main(void) {
#ifdef ROUND5_CCA_PKE
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);
    
    return example_run();
#else
    printf("This parameter set is not suitable for generating challenges. \n");
    return 0;
#endif
}
