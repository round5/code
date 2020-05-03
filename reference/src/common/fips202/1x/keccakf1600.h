#ifndef _KECCAKF1600_H_
#define _KECCAKF1600_H_

//	Importing, build upon:
#include <stddef.h> 
#include <stdint.h>

#ifdef AVX2
#include <immintrin.h>
#endif

#include "chooseparameters.h"

//	Reduction of public domain sources.

void KeccakF1600_StateExtractBytes ( uint64_t *state, uint8_t *data Parameters );

void KeccakF1600_StateXORBytes ( uint64_t *state, const uint8_t *data Parameters );

void KeccakF1600_StatePermute( uint64_t *state );

#ifdef AVX2
void KeccakF1600_StateExtractBytes_4x(__m256i *state,
                                      uint8_t *data0,
                                      uint8_t *data1,
                                      uint8_t *data2,
                                      uint8_t *data3
                                      Parameters );

void KeccakF1600_StateXORBytes_4x (__m256i *state,
                                   const uint8_t *data0,
                                   const uint8_t *data1,
                                   const uint8_t *data2,
                                   const uint8_t *data3
                                   Parameters );
#endif

#endif /* _KECCAKF1600_H_ */


