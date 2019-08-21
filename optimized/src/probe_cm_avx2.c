/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Koninklijke Philips N.V.
 */
#include "r5_parameter_sets.h"

#ifdef CM_CACHE

#ifdef AVX2

#include <immintrin.h>
#include "probe_cm.h"

#define PROBEVEC64  ((PARAMS_D + 63) / 64)

static const uint64_t VECM[4] =
{ 1L, 2L, 4L, 8L };

#if PARAMS_K != 1

inline int probe_cm(uint64_t *add, uint64_t *sub, const uint16_t x)  __attribute__((always_inline));

int probe_cm(uint64_t *add, uint64_t *sub, const uint16_t x)
{
    register __m256i vec0 = _mm256_setzero_si256();
    register __m256i vec1 = _mm256_set1_epi64x(1L);
    register __m256i vecc = vec0; // Indicating change, zero no change!
    register __m256i vecl = _mm256_slli_epi64(vec1, x & 0x3F); // low address part
    register __m256i vech = _mm256_slli_epi64(vec1, x >> 6  ); // high address part
    register __m256i vecm = _mm256_loadu_si256((const __m256i*) VECM);
    
    register __m256i vect, veca, vecb;
    
    for (int i = 0; i < (( PROBEVEC64+3)/4)*4; i+=4) {
        vect = _mm256_loadu_si256((__m256i*) &add[i]);
        veca = _mm256_or_si256(vect, _mm256_loadu_si256((__m256i*) &sub[i]));
        
        // Bit position.
        vecb = _mm256_andnot_si256(_mm256_cmpeq_epi64(_mm256_and_si256(vech, vecm), vec0), vecl);
        // Not if already occupied.
        vecb = _mm256_xor_si256( veca, _mm256_or_si256(veca, vecb));
        // Accumulate change.
        vecc = _mm256_or_si256(vecb, vecc);
        // Update value of add[i].
        _mm256_storeu_si256((__m256i*) &add[i], _mm256_xor_si256(vect, vecb));
        // Next 4 bits.
        vech = _mm256_srli_epi64( vech, 4 );
    }
    return _mm256_testz_si256(vecc, vecc); // return false if any change
}

#endif

#if PARAMS_K == 1

inline int probe_cm(uint64_t *v, const uint16_t x)  __attribute__((always_inline));

int probe_cm(uint64_t *v,  const uint16_t x)
{
    register __m256i vec0 = _mm256_setzero_si256();
    register __m256i vec1 = _mm256_set1_epi64x(1L);
    register __m256i vecc = vec0; // Indicating change, zero no change!
    register __m256i vecl = _mm256_slli_epi64(vec1, x & 0x3F); // low address part
    register __m256i vech = _mm256_slli_epi64(vec1, x >> 6  ); // high address part
    register __m256i vecm = _mm256_loadu_si256((const __m256i*) VECM);
    
    register __m256i veca, vecb;
    
    for (int i = 0; i < (( PROBEVEC64+3)/4)*4; i+=4) {
        veca = _mm256_loadu_si256((__m256i*) &v[i]);
        // Bit position.
        vecb = _mm256_andnot_si256(_mm256_cmpeq_epi64(_mm256_and_si256(vech, vecm), vec0), vecl);
        vecb = _mm256_or_si256(veca, vecb);
        // Accumulate change.
        vecc = _mm256_or_si256(vecc, _mm256_xor_si256( veca, vecb ));
        // Update value of add[i].
        _mm256_storeu_si256((__m256i*) &v[i], vecb);
        // Next 4 bits.
        vech = _mm256_srli_epi64( vech, 4 );
    }
    return _mm256_testz_si256(vecc, vecc); // return false if any change
}

#endif

#endif
#endif
