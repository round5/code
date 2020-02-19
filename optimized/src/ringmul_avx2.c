/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

// Constant-time code

#include "ringmul.h"

#if PARAMS_K == 1 && defined(CM_CT) && defined(AVX2)
#include <immintrin.h>
#include "drbg.h"
#include <string.h>

#define NUMCOEFS 16
#define SET1(a)         _mm256_set1_epi16(a)
#define MULT(a,b)       _mm256_mullo_epi16(a, b)
#define ADD(a,b)        _mm256_add_epi16(a, b)
#define EXTRACT(a,b)    _mm256_extract_epi16(a, b)
#define LOAD(a)         _mm256_lddqu_si256(a)
#define STORE(a,b)      _mm256_storeu_si256(a,b)

// multiplication mod q, result length n
void ringmul_q(modq_t d[PARAMS_N],
               modq_t a[PARAMS_N],
               tern_secret secret_vector) {
    
    uint16_t j, k;
    modq_t *b;
    
    modq_t p[2 * (PARAMS_N + 1) + NUMCOEFS] __attribute__ ((aligned(32))) = {0};
    
    // Note: order of coefficients a[1..n] is *NOT* reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = (modq_t) (-a[0]);
    for (k = 1; k < PARAMS_N; k++) {
        p[k] = (modq_t) (a[k - 1] - a[k]);
    }
    p[PARAMS_N] = a[PARAMS_N - 1];
    
    // Duplicate at the end
    memcpy(p + (PARAMS_N + 1), p, (PARAMS_N + 1) * sizeof (modq_t));
    
    // Initialize result
    memset(d, 0, PARAMS_N * sizeof (modq_t));
    
    b = &p[PARAMS_N + 1];
    
     __m256i d16[(PARAMS_N+NUMCOEFS-1)/NUMCOEFS] __attribute__ ((aligned(32))) = {0};
    register __m256i b16_0, b16_1, b16_2, b16_3;
    register __m256i secret_vector16, secret_vector16_1, secret_vector16_2, secret_vector16_3;

    for (k = 0; k< PARAMS_N-3; k+=4){

        secret_vector16     = SET1(secret_vector[k]);
        secret_vector16_1   = SET1(secret_vector[k+1]);
        secret_vector16_2   = SET1(secret_vector[k+2]);
        secret_vector16_3   = SET1(secret_vector[k+3]);

        for (j = 0; j < (PARAMS_N+NUMCOEFS-1)/NUMCOEFS; j+=1) {
            
            b16_0 = LOAD((__m256i*)(&b[NUMCOEFS*j]));
            b16_0 = MULT(b16_0, secret_vector16);
            b16_1 = LOAD((__m256i*)(&b[NUMCOEFS*j-1]));
            b16_1 = MULT(b16_1, secret_vector16_1);
            b16_2 = LOAD((__m256i*)(&b[NUMCOEFS*j-2]));
            b16_2 = MULT(b16_2, secret_vector16_2);
            b16_3 = LOAD((__m256i*)(&b[NUMCOEFS*j-3]));
            b16_3 = MULT(b16_3, secret_vector16_3);
            
            b16_0 = ADD(b16_0, b16_1);
            b16_2 = ADD(b16_2, b16_3);
            b16_0 = ADD(b16_0, b16_2);
            d16[j] = ADD(d16[j], b16_0);
        }
        b = b - 4;
        if (b == &p[PARAMS_N + 1] - 4*((PARAMS_N-3)/4))
            break;
    }

    for (k = 4*((PARAMS_N - 3)/4); PARAMS_N; k++){

        secret_vector16     = SET1(secret_vector[k]);

        for (j = 0; j < (PARAMS_N+NUMCOEFS-1)/NUMCOEFS; j+=1) {

            b16_0 = LOAD((__m256i*)(&b[NUMCOEFS*j]));
            b16_0 = MULT(b16_0, secret_vector16);

            d16[j] = ADD(d16[j], b16_0);
        }
        b--;
        if (b == &p[1])
            break;
    }

    for (j = 0; j < PARAMS_N/NUMCOEFS; j++){
        STORE((__m256i*) &d[NUMCOEFS*j], d16[j]);
    }

    uint16_t *pd16 = (uint16_t*) &d16[((PARAMS_N+NUMCOEFS-1)/NUMCOEFS)-1];
    for (j = NUMCOEFS*(PARAMS_N/NUMCOEFS); j < PARAMS_N; j++){
        d[j] = (modq_t) pd16[j - NUMCOEFS*(PARAMS_N/NUMCOEFS)];
    }
    
    // "unlift"
    d[0] = (uint16_t) (-d[0]);
    for (k = 1; k < PARAMS_N; ++k) {
        d[k] = (uint16_t) (d[k - 1] - d[k]);
    }
}

// multiplication mod p, result length mu
void ringmul_p(modp_t d[PARAMS_MU],
               modp_t input[PARAMS_N],
               tern_secret secret_vector) {
    
    size_t j, k;
    modq_t p[(PARAMS_MU + 2) + (PARAMS_N + 1)];
    modq_t  *b, *b0, *a;
    
    a = &p[0];
    b = &p[PARAMS_N + 1];
    // Note: order of coefficients p[1..N] is *NOT* reversed!
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[0] = (modq_t) (-input[0]);
    for (k = 1; k < PARAMS_N; k++) {
        p[k] = (modq_t) (input[k - 1] - input[k]);
    }
    p[PARAMS_N] = (modq_t) input[PARAMS_N - 1];

#else
    // With error correction we do not "lift"
    for (j=0; j<PARAMS_N;j++){p[j] = input[j];}
    p[PARAMS_N] = 0;
    p[PARAMS_N+1] = input[0];
    a++;
    b++;
#endif
    b0 = b;
    
    // Duplicate elements so we don't need to perform index modulo
    memcpy(p + (PARAMS_N + 1), p, (PARAMS_MU + 2) * sizeof (modq_t));
    
    // Initialize result
    memset(d, 0, PARAMS_MU * sizeof (modp_t));
    a++;
    
    __m256i d16[PARAMS_MU/NUMCOEFS] __attribute__ ((aligned(32))) = {0};
    
    register __m256i b16_0, b16_1, b16_2, b16_3;
    register __m256i secret_vector16, secret_vector16_1, secret_vector16_2, secret_vector16_3;

    for (k = 0; k< PARAMS_N-3; k+=4){
        
        secret_vector16     = SET1(secret_vector[k]);
        secret_vector16_1   = SET1(secret_vector[k+1]);
        secret_vector16_2   = SET1(secret_vector[k+2]);
        secret_vector16_3   = SET1(secret_vector[k+3]);

        for (j = 0; j < PARAMS_MU/NUMCOEFS; j++) {
            
            b16_0 = LOAD((__m256i*)(&b[NUMCOEFS*j]));
            b16_0 = MULT(b16_0, secret_vector16);
            b16_1 = LOAD((__m256i*)(&b[NUMCOEFS*j-1]));
            b16_1 = MULT(b16_1, secret_vector16_1);
            b16_2 = LOAD((__m256i*)(&b[NUMCOEFS*j-2]));
            b16_2 = MULT(b16_2, secret_vector16_2);
            b16_3 = LOAD((__m256i*)(&b[NUMCOEFS*j-3]));
            b16_3 = MULT(b16_3, secret_vector16_3);
            
            b16_0 = ADD(b16_0, b16_1);
            b16_2 = ADD(b16_2, b16_3);
            b16_0 = ADD(b16_0, b16_2);
            d16[j] = ADD(d16[j], b16_0);
            
        }
        for (j = NUMCOEFS*(PARAMS_MU/NUMCOEFS); j < PARAMS_MU; j++) {
            d[j] += b[j]*secret_vector[k] +
            b[j-1]*secret_vector[k+1] +
            b[j-2]*secret_vector[k+2] +
            b[j-3]*secret_vector[k+3];
        }
        b=b-4;
        if (b == b0 - 4*((PARAMS_N-3)/4))
            break;
    }
    
    for (k = 4*((PARAMS_N - 3)/4); k < PARAMS_N; k++) {
        secret_vector16 = SET1(secret_vector[k]);
        for (j = 0; j < PARAMS_MU/NUMCOEFS; j++) {
            b16_0 = LOAD((__m256i*)(&b[NUMCOEFS*j]));
            b16_0 = MULT(b16_0, secret_vector16);
            d16[j] = ADD(d16[j], b16_0);
        }
        for (j = NUMCOEFS*(PARAMS_MU/NUMCOEFS); j < PARAMS_MU; j++) {
            d[j] += (b[j]*secret_vector[k]);
        }
        b--;
        if (b == a)
            break;
    }

    for (j = 0; j < PARAMS_MU/NUMCOEFS; j++){
#if (PARAMS_P_BITS > 8)
        STORE((__m256i*) &d[NUMCOEFS*j], d16[j]);
#else
        for (k=0; k < 16 ; k++){
	        d[j*NUMCOEFS+k] = ((uint16_t*) &d16[j])[k];
        }
#endif
    }
    
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lifted" so we now need to "unlift"
    d[0] = (modp_t) (-d[0]);
    for (k = 1; k < PARAMS_MU; ++k) {
        d[k] = (modp_t) (d[k - 1] - d[k]);
    }
#endif
}

#endif /* PARAMS_K == 1 && defined(CM_CT) && defined(AVX2)   */
