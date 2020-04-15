/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the random A matrix creation function.
 */

#include "a_random.h"

#include "misc.h"
#include "little_endian.h"
#include "drbg.h"


#define NBLOCKS 8

#if (defined(AVX2) && defined(STANDALONE) )
#define AVX2SHAKE_A_GEN
#endif

void create_A_random(modq_t *A_random, const unsigned char *seed) {
    
    uint8_t c0, c1, c2, c3;
    c0 = 0 ; c1= 1; c2=2; c3=3;
    const uint8_t domain[4] = "AGEN";
    
    if (PARAMS_TAU == 2) {
        
#ifndef AVX2SHAKE_A_GEN
        AGeneration(&A_random[c0 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c0);
        AGeneration(&A_random[c1 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c1);
        AGeneration(&A_random[c2 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c2);
        AGeneration(&A_random[c3 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c3);
            
#if (NBLOCKS > 4)
        c0 = 4 ; c1= 5; c2=6; c3=7;
        
        AGeneration(&A_random[c0 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c0);
        AGeneration(&A_random[c1 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c1);
        AGeneration(&A_random[c2 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c2);
        AGeneration(&A_random[c3 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ], (PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS, domain, seed, &c3);
#endif
        
#else
      
        AGeneration4x(  &A_random[c0 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        &A_random[c1 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        &A_random[c2 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        &A_random[c3 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS),
                        domain,
                        seed,
                        &c0,
                        &c1,
                        &c2,
                        &c3);
        
#if NBLOCKS > 4
        
        c0 = 4 ; c1= 5; c2=6; c3=7;
        AGeneration4x(   &A_random[c0 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        &A_random[c1 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        &A_random[c2 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        &A_random[c3 * ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS) ],
                        ((PARAMS_TAU2_LEN+NBLOCKS-1)/NBLOCKS),
                        domain,
                        seed,
                        &c0,
                        &c1,
                        &c2,
                        &c3);
#endif
        
#endif
        
        
    } else {
        
#ifndef AVX2SHAKE_A_GEN
        
        if (PARAMS_K == 1){ // RING
            AGeneration(&A_random[c0 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c0);
            AGeneration(&A_random[c1 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c1);
            AGeneration(&A_random[c2 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c2);
            AGeneration(&A_random[c3 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c3);

#if (NBLOCKS > 4)
            c0 = 4 ; c1= 5; c2=6; c3=7;
            
            AGeneration(&A_random[c0 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c0);
            AGeneration(&A_random[c1 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c1);
            AGeneration(&A_random[c2 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c2);
            AGeneration(&A_random[c3 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ], (PARAMS_D+NBLOCKS-1)/NBLOCKS, domain, seed, &c3);

#endif
        } else { // NON_RING
            AGeneration(&A_random[c0 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c0);
            AGeneration(&A_random[c1 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c1);
            AGeneration(&A_random[c2 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c2);
            AGeneration(&A_random[c3 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c3);

#if (NBLOCKS > 4)
            c0 = 4 ; c1= 5; c2=6; c3=7;
            AGeneration(&A_random[c0 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c0);
            AGeneration(&A_random[c1 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c1);
            AGeneration(&A_random[c2 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c2);
            AGeneration(&A_random[c3 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D ], ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D, domain, seed, &c3);

#endif
        }
#else

        if (PARAMS_K == 1){ // RING
            AGeneration4x(   &A_random[c0 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               &A_random[c1 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               &A_random[c2 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               &A_random[c3 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               ((PARAMS_D+NBLOCKS-1)/NBLOCKS),
                               domain,
                               seed,
                               &c0,
                               &c1,
                               &c2,
                               &c3);

#if NBLOCKS > 4
            
            c0 = 4 ; c1= 5; c2=6; c3=7;
            AGeneration4x(   &A_random[c0 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               &A_random[c1 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               &A_random[c2 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               &A_random[c3 * ((PARAMS_D+NBLOCKS-1)/NBLOCKS) ],
                               ((PARAMS_D+NBLOCKS-1)/NBLOCKS),
                               domain,
                               seed,
                               &c0,
                               &c1,
                               &c2,
                               &c3);

#endif
            
        } else { // NON_RING
            AGeneration4x(     &A_random[c0 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               &A_random[c1 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               &A_random[c2 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               &A_random[c3 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D,
                               domain,
                               seed,
                               &c0,
                               &c1,
                               &c2,
                               &c3);

#if NBLOCKS > 4
            c0 = 4 ; c1= 5; c2=6; c3=7;
            AGeneration4x(     &A_random[c0 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               &A_random[c1 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               &A_random[c2 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               &A_random[c3 * ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D],
                               ((PARAMS_K+NBLOCKS-1)/NBLOCKS) * PARAMS_D,
                               domain,
                               seed,
                               &c0,
                               &c1,
                               &c2,
                               &c3);
            
#endif
        

        }
#endif
    }
}
