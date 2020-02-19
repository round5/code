/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the KEM functions (NIST api).
 */

#include "kem.h"

#include <stdlib.h>

#define ROUND5_CCA_PKE

#ifndef ROUND5_CCA_PKE

#include "r5_cpa_kem.h"

extern int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    DeclareParameters;
    return r5_cpa_kem_keygen(pk, sk Params);
}

extern int crypto_kem_enc(unsigned char *ct, unsigned char *k, const unsigned char *pk) {
    DeclareParameters;
    return r5_cpa_kem_encapsulate(ct, k, pk Params);
}

extern int crypto_kem_dec(unsigned char *k, const unsigned char *ct, const unsigned char *sk) {
    DeclareParameters;
    return r5_cpa_kem_decapsulate(k, ct, sk Params);
}

#else

#include "r5_cca_kem.h"

extern int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    DeclareParameters;
    return r5_cca_kem_keygen(pk, sk Params);
}

extern int crypto_kem_enc(unsigned char *ct, unsigned char *k, const unsigned char *pk) {
    DeclareParameters;
    return r5_cca_kem_encapsulate(ct, k, pk Params);
}

extern int crypto_kem_dec(unsigned char *k, const unsigned char *ct, const unsigned char *sk) {
    DeclareParameters;
    return r5_cca_kem_decapsulate(k, ct, sk Params);
}


#endif
