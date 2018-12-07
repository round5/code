/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan
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
 * Implementation of the SHAKE128, SHAKE256, cSHAKE128, and cSHAKE256 hash
 * functions.
 */

#include "shake.h"
#include <assert.h>

/* Use OpenSSL's Shake unless disabled/not supported */
#undef USE_OPENSSL_SHAKE
#ifndef NO_OPENSSL_SHAKE
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x1010100f
#define USE_OPENSSL_SHAKE
#include <openssl/evp.h>
#endif
#endif

/*******************************************************************************
 * Public functions
 ******************************************************************************/

extern void shake128_init(shake_ctx *ctx);
extern void shake128_absorb(shake_ctx *ctx, const unsigned char *input, const size_t input_len);
extern void shake128_squeezeblocks(shake_ctx *ctx, unsigned char *output, const size_t nr_blocks);

void shake128(unsigned char *output, size_t output_len, const unsigned char *input, const size_t input_len) {
#if defined(USE_OPENSSL_SHAKE)
    EVP_MD_CTX *md_ctx;
    if (!(md_ctx = EVP_MD_CTX_new())) {
        fprintf(stderr, "Error: Failed to create SHAKE128 context.\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestInit_ex(md_ctx, EVP_shake128(), NULL) != 1) {
        fprintf(stderr, "Error: Failed to initialize SHAKE128 context.\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestUpdate(md_ctx, input, input_len) != 1) {
        fprintf(stderr, "Error: Failed to update SHAKE128 context.\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestFinalXOF(md_ctx, (unsigned char *) output, output_len) != 1) {
        fprintf(stderr, "Error: Failed squeeze SHAKE128 context.\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(md_ctx);
#else
    shake_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, input, input_len);
    if (Keccak_HashSqueeze(&ctx, output, output_len * 8) != 0) {
        fprintf(stderr, "Error: Failed to squeeze SHAKE128 context\n");
        exit(EXIT_FAILURE);
    }
#endif
}

extern void shake256_init(shake_ctx *ctx);
extern void shake256_absorb(shake_ctx *ctx, const unsigned char *input, const size_t input_len);
extern void shake256_squeezeblocks(shake_ctx *ctx, unsigned char *output, const size_t nr_blocks);

void shake256(unsigned char *output, size_t output_len, const unsigned char *input, const size_t input_len) {
#if defined(USE_OPENSSL_SHAKE)
    EVP_MD_CTX *md_ctx;
    if (!(md_ctx = EVP_MD_CTX_new())) {
        fprintf(stderr, "Error: Failed to create SHAKE256 context.\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestInit_ex(md_ctx, EVP_shake256(), NULL) != 1) {
        fprintf(stderr, "Error: Failed to initialize SHAKE256 context.\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestUpdate(md_ctx, input, input_len) != 1) {
        fprintf(stderr, "Error: Failed to update SHAKE256 context.\n");
        exit(EXIT_FAILURE);
    }
    if (EVP_DigestFinalXOF(md_ctx, (unsigned char *) output, output_len) != 1) {
        fprintf(stderr, "Error: Failed squeeze SHAKE256 context.\n");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(md_ctx);
#else
    shake_ctx ctx;
    shake256_init(&ctx);
    shake256_absorb(&ctx, input, input_len);
    if (Keccak_HashSqueeze(&ctx, output, output_len * 8) != 0) {
        fprintf(stderr, "Error: Failed to squeeze SHAKE256 context\n");
        exit(EXIT_FAILURE);
    }
#endif
}

extern void cshake128_init(cshake_ctx *ctx, const unsigned char *customization, const size_t customization_len);
extern void cshake128_absorb(cshake_ctx *ctx, const unsigned char *input, const size_t input_len);
extern void cshake128_squeezeblocks(cshake_ctx *ctx, unsigned char *output, const size_t nr_blocks);
extern void cshake128(unsigned char *output, size_t output_len, const unsigned char *input, const size_t input_len, const unsigned char *customization, const size_t customization_len);

extern void cshake256_init(cshake_ctx *ctx, const unsigned char *customization, const size_t customization_len);
extern void cshake256_absorb(cshake_ctx *ctx, const unsigned char *input, const size_t input_len);
extern void cshake256_squeezeblocks(cshake_ctx *ctx, unsigned char *output, const size_t nr_blocks);
extern void cshake256(unsigned char *output, size_t output_len, const unsigned char *input, const size_t input_len, const unsigned char *customization, const size_t customization_len);
