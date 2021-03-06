/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

//  CPA Versions of KEM functionality

#include "r5_cpa_kem.h"
#include "r5_parameter_sets.h"
#include "r5_cpa_pke.h"
#include "r5_hash.h"
#include "drbg.h"
#include "rng.h"
#include "misc.h"

#include <stdlib.h>
#include <string.h>

// CPA-KEM KeyGen()

int r5_cpa_kem_keygen(uint8_t *pk, uint8_t *sk) {
    r5_cpa_pke_keygen(pk, sk);

    return 0;
}

// CPA-KEM Encaps()

int r5_cpa_kem_encapsulate(uint8_t *ct, uint8_t *k, const uint8_t *pk) {

    uint8_t m[PARAMS_KAPPA_BYTES];
    uint8_t rho[PARAMS_KAPPA_BYTES];
    
    int ret = 0;

    /* Generate a random m and rho */
    randombytes(m, PARAMS_KAPPA_BYTES);
    randombytes(rho, PARAMS_KAPPA_BYTES);

    ret = r5_cpa_pke_encrypt(ct, pk, m, rho);
    if (ret < 0){
        return ret;
    }

    HCPAKEM(k, PARAMS_KAPPA_BYTES, m, PARAMS_KAPPA_BYTES, ct, PARAMS_CT_SIZE);

    return ret;
}

// CPA-KEM Decaps()

int r5_cpa_kem_decapsulate(uint8_t *k, const uint8_t *ct, const uint8_t *sk) {

    uint8_t m[PARAMS_KAPPA_BYTES];

    int ret = 0;
    
    /* Decrypt m */
    ret = r5_cpa_pke_decrypt(m, sk, ct);
    if (ret < 0){
        return ret;
    }

    HCPAKEM(k, PARAMS_KAPPA_BYTES, m, PARAMS_KAPPA_BYTES, ct, PARAMS_CT_SIZE);
    
    return ret;
}
