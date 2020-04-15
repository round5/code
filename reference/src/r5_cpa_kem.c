/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the CPA KEM functions.
 */

#include "r5_cpa_kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r5_core.h"
#include "r5_cpa_pke.h"
#include "pack.h"
#include "r5_hash.h"
#include "misc.h"
#include "r5_memory.h"
#include "rng.h"
#include "drbg.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cpa_kem_keygen(unsigned char *pk, unsigned char *sk Parameters) {
    return r5_cpa_pke_keygen(pk, sk Params);
}

int r5_cpa_kem_encapsulate(unsigned char *ct, unsigned char *k, const unsigned char *pk Parameters) {
    unsigned char *rho;
    unsigned char *m;

    /* Generate a random m */
    m = checked_malloc(PARAMS_KAPPA_BYTES);
    randombytes(m, PARAMS_KAPPA_BYTES);

    /* Randomly generate rho */
    rho = checked_malloc(PARAMS_KAPPA_BYTES);
    randombytes(rho, PARAMS_KAPPA_BYTES);

    /* Encrypt m */
    r5_cpa_pke_encrypt(ct, pk, m, rho Params);

    HCPAKEM(k, PARAMS_KAPPA_BYTES, m, PARAMS_KAPPA_BYTES, ct, PARAMS_CT_SIZE Params);
    
    free(rho);
    free(m);

    return 0;
}

int r5_cpa_kem_decapsulate(unsigned char *k, const unsigned char *ct, const unsigned char *sk Parameters) {

    unsigned char *m;

    /* Allocate space */
    m = checked_malloc(PARAMS_KAPPA_BYTES);

    /* Decrypt m */
    r5_cpa_pke_decrypt(m, sk, ct Params);

    HCPAKEM(k, PARAMS_KAPPA_BYTES, m, PARAMS_KAPPA_BYTES, ct, PARAMS_CT_SIZE Params);
   
    free(m);

    return 0;
}
