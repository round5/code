/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the CCA KEM functions.
 */

#include "r5_cca_kem.h"

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
 * Private functions
 ******************************************************************************/

/**
 * Verifies whether or not two byte strings are equal (in constant time).
 *
 * @param s1 the byte string to compare to
 * @param s2 the byte string to compare
 * @param n the number of bytes to compare
 * @return 0 if all size bytes are equal, non-zero otherwise
 */
static int verify(const void *s1, const void *s2, size_t n) {
    return constant_time_memcmp(s1, s2, n);
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cca_kem_keygen(unsigned char *pk, unsigned char *sk Parameters) {
    unsigned char *y = checked_malloc(PARAMS_KAPPA_BYTES);

    /* Generate the base key pair */
    r5_cpa_pke_keygen(pk, sk Params);

    /* Append y and pk to sk */
    randombytes(y, PARAMS_KAPPA_BYTES);
    memcpy(sk + PARAMS_KAPPA_BYTES, y, PARAMS_KAPPA_BYTES);
    memcpy(sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);

    free(y);

    return 0;
}

int r5_cca_kem_encapsulate(unsigned char *ct, unsigned char *k, const unsigned char *pk Parameters) {
    unsigned char *hash_input;
    unsigned char *m;
    unsigned char *L_g_rho;

    /* Allocate space */
    hash_input = checked_malloc((size_t) (PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE));
    m = checked_malloc(PARAMS_KAPPA_BYTES);
    L_g_rho = checked_malloc(3U * PARAMS_KAPPA_BYTES);

    /* Generate random m */
    randombytes(m, PARAMS_KAPPA_BYTES);

    /* Determine l, g, and rho */
    memcpy(hash_input, m, PARAMS_KAPPA_BYTES);
    memcpy(hash_input + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);
    hash(L_g_rho, 3U * PARAMS_KAPPA_BYTES, hash_input, (size_t) (PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE) Params);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    print_hex("r5_cca_kem_encapsulate: m", m, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_encapsulate: L", L_g_rho, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_encapsulate: g", L_g_rho + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_encapsulate: rho", L_g_rho + 2 * PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, 1);
#endif

    /* Encrypt m: ct = (U^T,v) */
    r5_cpa_pke_encrypt(ct, pk, m, L_g_rho + 2 * PARAMS_KAPPA_BYTES Params);

    /* Append g: ct = (U^T,v,g) */
    memcpy(ct + PARAMS_CT_SIZE, L_g_rho + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES);

    /* k = H(L, ct) */
    hash_input = checked_realloc(hash_input, (size_t) (PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES));
    memcpy(hash_input, L_g_rho, PARAMS_KAPPA_BYTES);
    memcpy(hash_input + PARAMS_KAPPA_BYTES, ct, (size_t) (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES));
    hash(k, PARAMS_KAPPA_BYTES, hash_input, (size_t) (PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES) Params);

    free(hash_input);
    free(L_g_rho);
    free(m);

    return 0;
}

int r5_cca_kem_decapsulate(unsigned char *k, const unsigned char *ct, const unsigned char *sk Parameters) {
    unsigned char *hash_input;
    unsigned char *m_prime;
    unsigned char *L_g_rho_prime;
    unsigned char *ct_prime;
    const unsigned char *y = sk + PARAMS_KAPPA_BYTES; /* y is located after the sk */
    const unsigned char *pk = y + PARAMS_KAPPA_BYTES; /* pk is located after y  */

    /* Allocate space */
    hash_input = checked_malloc((size_t) (PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE));
    m_prime = checked_malloc(PARAMS_KAPPA_BYTES);
    L_g_rho_prime = checked_malloc(3U * PARAMS_KAPPA_BYTES);
    ct_prime = checked_malloc((size_t) (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES));

    /* Decrypt m' */
    r5_cpa_pke_decrypt(m_prime, sk, ct Params);

    /* Determine l', g', and rho' from m' */
    memcpy(hash_input, m_prime, PARAMS_KAPPA_BYTES);
    memcpy(hash_input + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);
    hash(L_g_rho_prime, 3U * PARAMS_KAPPA_BYTES, hash_input, (size_t) (PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE) Params);

#if defined(NIST_KAT_GENERATION) || defined(DEBUG)
    print_hex("r5_cca_kem_decapsulate: m_prime", m_prime, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_decapsulate: L_prime", L_g_rho_prime, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_decapsulate: g_prime", L_g_rho_prime + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, 1);
    print_hex("r5_cca_kem_decapsulate: rho_prime", L_g_rho_prime + 2 * PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, 1);
#endif

    /* Encrypt m: ct' = (U'^T,v') */
    r5_cpa_pke_encrypt(ct_prime, pk, m_prime, L_g_rho_prime + 2 * PARAMS_KAPPA_BYTES Params);
    /* Append g': ct' = (U'^T,v',g') */
    memcpy(ct_prime + PARAMS_CT_SIZE, L_g_rho_prime + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES);

    /* k = H(L', ct') or k = H(y, ct') depending on fail status */
    hash_input = checked_realloc(hash_input, (size_t) (PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES));
    uint8_t fail = (uint8_t) verify(ct, ct_prime, (size_t) (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES));
    memcpy(hash_input, L_g_rho_prime, PARAMS_KAPPA_BYTES);
    memcpy(hash_input + PARAMS_KAPPA_BYTES, ct_prime, (size_t) (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES));
    conditional_constant_time_memcpy(hash_input, y, PARAMS_KAPPA_BYTES, fail); /* Overwrite L' with y in case of failure */
    hash(k, PARAMS_KAPPA_BYTES, hash_input, (size_t) (PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES) Params);

    free(hash_input);
    free(m_prime);
    free(L_g_rho_prime);
    free(ct_prime);

    return 0;
}
