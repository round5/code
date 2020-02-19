/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Example KEM application.
 */


#ifdef TIMING

#if (TIMING > 1)
#define NUMRUNS TIMING
#else
#define NUMRUNS 1000
#endif

#include <time.h>
#include <math.h>
// measuring CPU cycles
#if defined(__x86_64__)
#define CPU_CYCLE_COUNT(v) __asm__ __volatile__("rdtsc; shlq $32,%%rdx;orq %%rdx,%%rax" : "=a" (v) : : "memory", "%rdx")
#elif defined(__i386__)
unsigned int lo, hi;
#define CPU_CYCLE_COUNT(v)  __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi)); v = ((uint64_t)hi << 32) | lo
#else
#warning Can not run speed tests on non i386 platform
#define CPU_CYCLE_COUNT(v)  v = 0
#endif

#define EXECUTE_AND_MEASURE_TIME(index, iteration, code) \
start = clock(); \
CPU_CYCLE_COUNT(cpu_start);\
code; \
end = clock(); \
CPU_CYCLE_COUNT(cpu_end);\
cpu_cycles_used[index][iteration] = (double)(cpu_end - cpu_start); \
cpu_time_used[index][iteration] = (double)(end - start) / CLOCKS_PER_SEC;

#define PRINT(code)

#else

#define NUMRUNS 1
#define EXECUTE_AND_MEASURE_TIME(index, iteration, code) code;
#define PRINT(code) code;

#endif

#include "kem.h"
#include "rng.h"
#include "r5_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if PARAMS_TAU == 1 && PARAMS_N == 1
#include "a_fixed.h"
#endif

#ifdef TIMING
double f_mean(uint32_t num, double cpu_time_used[NUMRUNS]){
    uint32_t j;
    double mean = 0;
    for (j = 0; j< num; j++){
        mean += cpu_time_used[j];
    }
    return mean =mean/num;
}

double f_var(uint32_t num, double v_mean, double cpu_time_used[NUMRUNS]){
    uint32_t j;
    double var = 0;
    for (j = 0; j< num; j++){
        var += (cpu_time_used[j]-v_mean)*(cpu_time_used[j]-v_mean) ;
    }
    return var =var/num;
}

#else

static void print_parameters() {
    
    printf("This set of parameters correspond to NIST security level %c.\n", CRYPTO_ALGNAME[5]);
    
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
#endif

/**
 * Runs an example flow of the algorithm.
 *
 * @return __0__ in case of success
 */
static int example_run() {
    
    int ok = 0;

    
    printf("CRYPTO_ALGNAME        =%s\n", CRYPTO_ALGNAME);
    printf("CRYPTO_SECRETKEYBYTES =%u\n", CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_PUBLICKEYBYTES =%u\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_BYTES          =%u\n", CRYPTO_BYTES);
    printf("CRYPTO_CIPHERTEXTBYTES=%u\n", CRYPTO_CIPHERTEXTBYTES);
    
    PRINT(print_parameters())

#if PARAMS_TAU == 1 && PARAMS_N == 1
    unsigned char seed[PARAMS_KAPPA_BYTES];
    randombytes(seed, PARAMS_KAPPA_BYTES);
    PRINT(print_hex("Generated A using seed", seed, PARAMS_KAPPA_BYTES, 1))
    create_A_fixed(seed);
#endif

#ifdef TIMING
    clock_t start, end;
    uint64_t cpu_start, cpu_end;
    double cpu_time_used[3][NUMRUNS];
    double cpu_cycles_used[3][NUMRUNS];
    double v_mean[3];
    double mean_cpu[3];
#endif
    
    for (int iteration = 0 ; iteration < NUMRUNS ; iteration++){
    
        /* Set up message containers */
        unsigned char sk[CRYPTO_SECRETKEYBYTES];
        unsigned char pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
        unsigned char ss_i[CRYPTO_BYTES], ss_r[CRYPTO_BYTES];
        
        /* Initiator */
        PRINT(printf("Initiator sets up key pair\n"))
        EXECUTE_AND_MEASURE_TIME(0, iteration, crypto_kem_keypair(pk, sk))
        PRINT(print_hex("PK", pk, CRYPTO_PUBLICKEYBYTES, 1))
        PRINT(print_hex("SK", sk, PARAMS_KAPPA_BYTES, 1))

        /* Initiator sends his pk */
        PRINT(printf("Initiator sends his public key\n");)

        /* Responder */
        PRINT(printf("Responder determines shared secret, encapsulates and sends the cipher text\n"))
        EXECUTE_AND_MEASURE_TIME(1, iteration, crypto_kem_enc(ct, ss_r, pk))
        PRINT(print_hex("CT", ct, CRYPTO_CIPHERTEXTBYTES, 1))

        /* Initiator */
        PRINT(printf("Initiator de-encapsulates cipher text and determines shared secret\n"))
        EXECUTE_AND_MEASURE_TIME(2, iteration, crypto_kem_dec(ss_i, ct, sk))
        PRINT(printf("\n"))

        PRINT(printf("Comparing shared secrets: %s\n", memcmp(ss_r, ss_i, CRYPTO_BYTES) ? "NOT OK" : "OK"))
        
        ok += memcmp(ss_r, ss_i, CRYPTO_BYTES);

        PRINT(printf("\n"))
        PRINT(print_hex("SharedSecret(R)", ss_r, CRYPTO_BYTES, 1))
        PRINT(print_hex("SharedSecret(I)", ss_i, CRYPTO_BYTES, 1))
    }

    #ifdef TIMING
    if (ok == 0){
        printf("\nSuccess in all %i KEM executions \n", NUMRUNS);
    } else {
        printf("\nFailures in KEM executions \n");
    }
    
    printf(" \n");
    mean_cpu[0] = f_mean(NUMRUNS, cpu_cycles_used[0]);
    printf("KeyGen(mean): %u K CPU cycles \n", (uint32_t)(mean_cpu[0]/1000));
    v_mean[0] = f_mean(NUMRUNS, cpu_time_used[0]);
    printf("KeyGen(mean): %f ms \n", 1000*v_mean[0]);
    printf("KeyGen(sd)  : %f ms \n", 1000*sqrt(f_var(NUMRUNS, v_mean[0], cpu_time_used[0])));
    
    mean_cpu[1] = f_mean(NUMRUNS, cpu_cycles_used[1]);
    printf("Enc   (mean): %u K CPU cycles \n", (uint32_t)(mean_cpu[1]/1000));
    v_mean[1] = f_mean(NUMRUNS, cpu_time_used[1]);
    printf("Enc   (mean): %f ms \n", 1000*v_mean[1]);
    printf("Enc   (sd)  : %f ms \n", 1000*sqrt(f_var(NUMRUNS, v_mean[1], cpu_time_used[1])));
    
    mean_cpu[2] = f_mean(NUMRUNS, cpu_cycles_used[2]);
    printf("Dec   (mean): %u K CPU cycles \n", (uint32_t)(mean_cpu[2]/1000));
    v_mean[2] = f_mean(NUMRUNS, cpu_time_used[2]);
    printf("Dec   (mean): %f ms \n", 1000*v_mean[2]);
    printf("Dec   (sd)  : %f ms \n", 1000*sqrt(f_var(NUMRUNS, v_mean[2], cpu_time_used[2])));
    printf(" =================================== \n");
    printf("Total (mean): %f ms \n", 1000*(v_mean[0]+v_mean[1]+v_mean[2]));
    printf("Total (mean): %u K CPU cycles \n", (uint32_t)((mean_cpu[0]+mean_cpu[1]+mean_cpu[2])/1000));
    #endif
    
    
    return ok;
}

/**
 * Main program, runs an example algorithm flow.
 *
 * @return __0__ in case of success
 */
int main(void) {
    /* Initialize random bytes RNG */
    unsigned char entropy_input[48];
    for (int i = 0; i < 48; i++) {
        entropy_input[i] = (unsigned char) i;
    }
    randombytes_init(entropy_input, NULL, 256);

    return example_run();
}
