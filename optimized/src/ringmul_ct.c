/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

// Constant-time code

#include "ringmul.h"

#if PARAMS_K == 1 && defined(CM_CT)  && !defined(AVX2)

#include "drbg.h"

// multiplication mod q, result length n
void ringmul_q(modq_t d[PARAMS_N],
               modq_t a[PARAMS_N],
               tern_secret secret_vector) {
    
    size_t j, k;
    modq_t *b;
    
    modq_t p[2 * (PARAMS_N + 1)];
    
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

    b = &p[PARAMS_D + 1];

    for (k = 0; k< PARAMS_D; k++){
            // implement with multiplication
            for (j = 0; j < PARAMS_D; j++) {
                d[j] += b[j]*secret_vector[k];
            }
            b--;
            if (b == &p[1])
                break;
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
    modp_t p[(PARAMS_MU + 2) + (PARAMS_N + 1)];
    modp_t  *b, *a;
    
    a = &p[0];
    b = &p[PARAMS_N + 1];
    // Note: order of coefficients p[1..N] is *NOT* reversed!
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[0] = (modp_t) (-input[0]);
    for (k = 1; k < PARAMS_N; k++) {
        p[k] = (modp_t) (input[k - 1] - input[k]);
    }
    p[PARAMS_N] = input[PARAMS_N - 1];
#else
    // With error correction we do not "lift"
    memcpy(p, input, PARAMS_N * sizeof (modp_t));
    p[PARAMS_N] = 0;
    p[PARAMS_N+1] = input[0];
    a++;
    b++;
#endif
    
    // Duplicate elements so we don't need to perform index modulo
    memcpy(p + (PARAMS_N + 1), p, (PARAMS_MU + 2) * sizeof (modp_t));
    
    // Initialize result
    memset(d, 0, (PARAMS_MU) * sizeof (modp_t));
    a++;
    
    for (k = 0; k < PARAMS_N; k++) {
            for (j = 0; j < PARAMS_MU; j++) {
                d[j] += b[j]*secret_vector[k];
            }
            b--;
            if (b == a)
                break;
    }
    
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lifted" so we now need to "unlift"
    d[0] = (modp_t) (-d[0]);
    for (k = 1; k < PARAMS_MU; ++k) {
        d[k] = (modp_t) (d[k - 1] - d[k]);
    }
#endif
}



#endif /* PARAMS_K == 1 && defined(CM_CACHE) */
