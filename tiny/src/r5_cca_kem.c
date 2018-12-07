/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Hayo Baan
 *
 * All rights reserved. A copyright license for redistribution and use in
 * source and binary forms, with or without modification, is hereby granted for
 * non-commercial, experimental, research, public review and evaluation
 * purposes, provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "r5_cpa_pke.h"
#include "parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r5_hash.h"
#include "rng.h"
#include "misc.h"
#include "r5_memory.h"

// CCA-KEM KeyGen()

int r5_cca_kem_keygen(uint8_t *pk, uint8_t *sk) {
    uint8_t y[PARAMS_KAPPA_BYTES];

    /* Generate the base key pair */
    r5_cpa_pke_keygen(pk, sk);

    /* Append y and pk to sk */
    randombytes(y, PARAMS_KAPPA_BYTES);
    memcpy(sk + PARAMS_KAPPA_BYTES, y, PARAMS_KAPPA_BYTES);
    memcpy(sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);

    return 0;
}

// CCA-KEM Encaps()

int r5_cca_kem_encapsulate(uint8_t *ct, uint8_t *k, const uint8_t *pk) {
    uint8_t hash_in[PARAMS_KAPPA_BYTES + (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES > PARAMS_PK_SIZE ? PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES : PARAMS_PK_SIZE)];
    uint8_t m[PARAMS_KAPPA_BYTES];
    uint8_t L_g_rho[3][PARAMS_KAPPA_BYTES];

    randombytes(m, PARAMS_KAPPA_BYTES); // generate random m

    memcpy(hash_in, m, PARAMS_KAPPA_BYTES); // G: (l | g | rho) = h(m | pk);
    memcpy(hash_in + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);
    hash((uint8_t *) L_g_rho, 3 * PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE, PARAMS_KAPPA_BYTES);

#if defined(ROUND5_INTERMEDIATE) || defined(DEBUG)
    print_hex("cca_encrypt: m", m, PARAMS_KAPPA_BYTES, 1);
    print_hex("cca_encrypt: L", L_g_rho[0], PARAMS_KAPPA_BYTES, 1);
    print_hex("cca_encrypt: g", L_g_rho[1], PARAMS_KAPPA_BYTES, 1);
    print_hex("cca_encrypt: rho", L_g_rho[2], PARAMS_KAPPA_BYTES, 1);
#endif

    /* Encrypt  */
    r5_cpa_pke_encrypt(ct, pk, m, L_g_rho[2]); // m: ct = (U,v)

    /* Append g: ct = (U,v,g) */
    memcpy(ct + PARAMS_CT_SIZE, L_g_rho[1], PARAMS_KAPPA_BYTES);

    /* k = H(L, ct) */
    memcpy(hash_in, L_g_rho[0], PARAMS_KAPPA_BYTES);
    memcpy(hash_in + PARAMS_KAPPA_BYTES,
            ct, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    hash(k, PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES);

    return 0;
}

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

// CCA-KEM Decaps()

int r5_cca_kem_decapsulate(uint8_t *k, const uint8_t *ct, const uint8_t *sk) {
    uint8_t hash_in[PARAMS_KAPPA_BYTES + (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES > PARAMS_PK_SIZE ? PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES : PARAMS_PK_SIZE)];
    uint8_t m_prime[PARAMS_KAPPA_BYTES];
    uint8_t L_g_rho_prime[3][PARAMS_KAPPA_BYTES];
    uint8_t ct_prime[PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];
    uint8_t fail;

    r5_cpa_pke_decrypt(m_prime, sk, ct); // r5_cpa_pke_decrypt m'

    memcpy(hash_in, m_prime, PARAMS_KAPPA_BYTES);
    memcpy(hash_in + PARAMS_KAPPA_BYTES, // (L | g | rho) = h(m | pk)
            sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, PARAMS_PK_SIZE);
    hash((uint8_t *) L_g_rho_prime, 3 * PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE, PARAMS_KAPPA_BYTES);

#if defined(ROUND5_INTERMEDIATE) || defined(DEBUG)
    print_hex("cca_decrypt: m_prime", m_prime, PARAMS_KAPPA_BYTES, 1);
    print_hex("cca_decrypt: L_prime", L_g_rho_prime[0], PARAMS_KAPPA_BYTES, 1);
    print_hex("cca_decrypt: g_prime", L_g_rho_prime[1], PARAMS_KAPPA_BYTES, 1);
    print_hex("cca_decrypt: rho_prime", L_g_rho_prime[2], PARAMS_KAPPA_BYTES, 1);
#endif

    // Encrypt m: ct' = (U',v')
    r5_cpa_pke_encrypt(ct_prime, sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, m_prime, L_g_rho_prime[2]);

    // ct' = (U',v',g')
    memcpy(ct_prime + PARAMS_CT_SIZE, L_g_rho_prime[1], PARAMS_KAPPA_BYTES);

    // k = H(L', ct')
    memcpy(hash_in, L_g_rho_prime[0], PARAMS_KAPPA_BYTES);
    // verification ok ?
    fail = (uint8_t) verify(ct, ct_prime, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    // k = H(y, ct') depending on fail state
    conditional_constant_time_memcpy(hash_in, sk + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, fail);

    memcpy(hash_in + PARAMS_KAPPA_BYTES, ct_prime, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    hash(k, PARAMS_KAPPA_BYTES, hash_in, PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES);

    return 0;
}
