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

#ifndef _API_H_
#define _API_H_

#include "parameters.h"

#ifndef ROUND5_CCA_PKE

/*
    This is the API defined by NIST for PQC KEMs.

    Public key:     unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    Secret key:     unsigned char sk[CRYPTO_SECRETKEYBYTES];
    Ciphertext:     unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    Shared secret:  unsigned char k[CRYPTO_BYTES];

    The functions always return 0. In case of decryption error the shared
    secrets from crypto_kem_enc() and crypto_kem_dec() simply won't match.
 */

// Key generation: (pk, sk) = r5_cpa_kem_keygen()

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

// Encapsulate: (ct, k) = r5_cpa_kem_encapsulate(pk)

int crypto_kem_enc(unsigned char *ct, unsigned char *k, const unsigned char *pk);

// Decapsulate: k = r5_cpa_kem_decapsulate(ct, sk)

int crypto_kem_dec(unsigned char *k, const unsigned char *ct, const unsigned char *sk);

#else

/*
    This is the API defined by NIST for PQC PKEs.

    Public key:     unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    Secret key:     unsigned char sk[CRYPTO_SECRETKEYBYTES];
    Ciphertext:     unsigned char ct[CRYPTO_BYTES] + message length;

    The functions always return 0. In case of decryption error the message
    simply won't match.
 */

// Key generation: (pk, sk) = r5_cca_pke_keygen()

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk);

// Encrypt: (ct) = r5_cca_pke_encrypt(m, pk)

int crypto_encrypt(unsigned char *ct, unsigned long long *ct_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk);

// Decrypt: (m) = r5_cca_pke_decrypt(ct, sk)

int crypto_encrypt_open(unsigned char *m, unsigned long long *m_len, const unsigned char *ct, unsigned long long ct_len, const unsigned char *sk);

#endif /* ROUND5_CCA_PKE */

#endif /* _API_H_ */
