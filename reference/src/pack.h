/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan, Jose Luis Torre Arce
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

/**
 * @file
 * Declaration of the various pack and unpack functions.
 */

#ifndef PACK_H
#define PACK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Packs the given vector using the specified number of bits per element.
     *
     * @param[out] packed  the buffer for the packed vector
     * @param[in]  m       the vector to pack
     * @param[in]  els     the number of elements
     * @param[in]  nr_bits the number of significant bits value
     * @return the length of the packed vector in bytes
     */
    size_t pack(unsigned char *packed, const uint16_t *m, const size_t els, const uint8_t nr_bits);

    /**
     * Unpacks the given vector using the specified number of bits per element.
     *
     * @param[in]  m       unpacked vector
     * @param[in]  packed  the packed vector
     * @param[in]  els     number of elements
     * @param[in]  nr_bits number of significant bits per element
     * @return total number of packed bytes processed
     */
    size_t unpack(uint16_t *m, const unsigned char *packed, const size_t els, const uint8_t nr_bits);

    /**
     * Packs a public key from its sigma and B components.
     *
     * @param[out] packed_pk the packed key
     * @param[in]  sigma     sigma
     * @param[in]  sigma_len length of sigma
     * @param[in]  B         B
     * @param[in]  elements  number of elements of B
     * @param[in]  nr_bits   number of significant bits per element
     * @return the length of packed pk in bytes
     */
    size_t pack_pk(unsigned char *packed_pk, const unsigned char *sigma, size_t sigma_len, const uint16_t *B, size_t elements, uint8_t nr_bits);

    /**
     * Unpacks a packed public key into its sigma and B components.
     *
     * @param[out] sigma     sigma
     * @param[out] B         B
     * @param[in]  packed_pk packed public key
     * @param[in]  sigma_len length of sigma
     * @param[in]  elements  the number of elements of B
     * @param[in]  nr_bits   the number of significant bits per element
     * @return total unpacked bytes
     */
    size_t unpack_pk(unsigned char *sigma, uint16_t *B, const unsigned char *packed_pk, size_t sigma_len, size_t elements, uint8_t nr_bits);

    /**
     * Packs the given ciphertext
     *
     * @param[out] packed_ct buffer for the packed ciphertext
     * @param[in]  U         matrix U
     * @param[in]  U_els     elements in U
     * @param[in]  U_bits    significant bits per element
     * @param[in]  v         vector v
     * @param[in]  v_els     elements in v
     * @param[in]  v_bits    significant bits per element
     * @return the length of packed ct in bytes
     */
    size_t pack_ct(unsigned char *packed_ct, const uint16_t *U, size_t U_els, uint8_t U_bits, const uint16_t *v, size_t v_els, uint8_t v_bits);

    /**
     * Unpacks the given ciphertext into its U and v components.
     *
     * @param[out] U         matrix U
     * @param[out] v         vector v
     * @param[in]  packed_ct packed ciphertext
     * @param[in]  U_els     elements in U
     * @param[in]  U_bits    significant bits per element
     * @param[in]  v_els     elements in v
     * @param[in]  v_bits    significant bits per element
     * @return total unpacked bytes
     */
    size_t unpack_ct(uint16_t *U, uint16_t *v, const unsigned char *packed_ct, const size_t U_els, const uint8_t U_bits, const size_t v_els, const uint8_t v_bits);

#ifdef __cplusplus
}
#endif

#endif /* PACK_H */
