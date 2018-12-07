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

//  CPA Versions of KEM functionality

#include "api.h"

#ifndef ROUND5_CCA_PKE

#include <stdlib.h>
#include <string.h>

#include "r5_cpa_pke.h"
#include "r5_hash.h"
#include "rng.h"
#include "misc.h"

// CPA-KEM KeyGen()

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {
    r5_cpa_pke_keygen(pk, sk);

    return 0;
}

// CPA-KEM Encaps()

int crypto_kem_enc(uint8_t *ct, uint8_t *k, const uint8_t *pk) {
    uint8_t hash_input[PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE];

    uint8_t m[PARAMS_KAPPA_BYTES];
    uint8_t rho[PARAMS_KAPPA_BYTES];

    /* Generate a random m and rho */
    randombytes(m, PARAMS_KAPPA_BYTES);
    randombytes(rho, PARAMS_KAPPA_BYTES);

    r5_cpa_pke_encrypt(ct, pk, m, rho);

    /* k = H(m, ct) */
    memcpy(hash_input, m, PARAMS_KAPPA_BYTES);
    memcpy(hash_input + PARAMS_KAPPA_BYTES, ct, PARAMS_CT_SIZE);
    hash(k, PARAMS_KAPPA_BYTES, hash_input, PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE, PARAMS_KAPPA_BYTES);

    return 0;
}

// CPA-KEM Decaps()

int crypto_kem_dec(uint8_t *k, const uint8_t *ct, const uint8_t *sk) {
    uint8_t hash_input[PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE];
    uint8_t m[PARAMS_KAPPA_BYTES];

    /* Decrypt m */
    r5_cpa_pke_decrypt(m, sk, ct);

    /* k = H(m, ct) */
    memcpy(hash_input, m, PARAMS_KAPPA_BYTES);
    memcpy(hash_input + PARAMS_KAPPA_BYTES, ct, PARAMS_CT_SIZE);
    hash(k, PARAMS_KAPPA_BYTES, hash_input, PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE, PARAMS_KAPPA_BYTES);

    return 0;
}

#endif /* !ROUND5_CCA_PKE */
