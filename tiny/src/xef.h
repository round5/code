/*
 * Copyright (c) 2018, PQShield
 * Markku-Juhani O. Saarinen
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

//  Generic prototypes for error correction code

#ifndef _XEF_H_
#define _XEF_H_

#include <stdint.h>
#include <stddef.h>

//  Parametrized versions. f = 0..5, number of errors fixed

//  Computes the parity code, XORs it at the end of payload
//  len = payload (bytes). Returns (payload | xef) length in *bits*.
size_t xef_compute(void *block, size_t len, unsigned f);

//  Fixes errors based on parity code. Call xef_compute() first to get delta.
//  len = payload (bytes). Returns (payload | xef) length in *bits*.
size_t xef_fixerr(void *block, size_t len, unsigned f);

// No unnecessary parameter passing with fast implementations
// (these prototypes are just for verifying fast implementations)

// Add error correction to (payload | xef). On first round, zeroize xef.
void xe_compute(void *block);

// fix errors on block (payload | xef)
void xe_fixerr(void *block);

// specific codes from optimized implementations
void xe5_190_compute(void *block);
void xe5_190_fixerr(void *block);
void xe5_218_compute(void *block);
void xe5_218_fixerr(void *block);
void xe5_234_compute(void *block);
void xe5_234_fixerr(void *block);

#endif /* _XEF_H_ */
