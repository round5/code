/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the encrypt and decrypt functions based on the CCA KEM
 * algorithm (NIST api).
 */

#include "pke.h"
#include <stdio.h>

#define ROUND5_CCA_PKE

#ifdef ROUND5_CCA_PKE
//#if CRYPTO_CIPHERTEXTBYTES == 0

#include "r5_cca_pke.h"

//extern int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk);
//extern int crypto_encrypt(unsigned char *ct, unsigned long long *ct_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk);
//extern int crypto_encrypt_open(unsigned char *m, unsigned long long *m_len, const unsigned char *ct, const unsigned long long ct_len, const unsigned char *sk);

extern int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk) {
    DeclareParameters;
    return r5_cca_pke_keygen(pk, sk Params);
}

extern int crypto_encrypt(unsigned char *ct, unsigned long long *ct_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk) {
    DeclareParameters;
    return r5_cca_pke_encrypt(ct, ct_len, m, m_len, pk Params);
}

extern int crypto_encrypt_open(unsigned char *m, unsigned long long *m_len, const unsigned char *ct, unsigned long long ct_len, const unsigned char *sk) {
    DeclareParameters;
    return r5_cca_pke_decrypt(m, m_len, ct, ct_len, sk Params);
}

#endif
