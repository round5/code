/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#include "r5_secretkeygen.h"
#include "drbg.h"
#ifdef AVX2
#include <immintrin.h>
#endif

#define CTSECRETVECTOR64_4 4*((CTSECRETVECTOR64+3)/4)

#ifndef SHIFT_LEFT64_CONSTANT_TIME

/**
 * Constant-time 64-bit left shift of 1. Use when 64-bit shifts may not
 * be constant-time on platform.
 *
 * @param out output variable (64-bit)
 * @param shift_amount the number of bits to shift the value 1 to the left
 * @param flag flag to indicate the shift amount can be >= 32
 * @return 1 << shift_amount
 */
#define constant_time_shift_1_left64(out, shift_amount, flag) do { \
uint64_t tmp; \
out = 1llu; \
tmp = (uint64_t) (-((shift_amount) & 1)); \
out = ((out << 1) & tmp) ^ (out & ~tmp); \
tmp = (uint64_t) (-(((shift_amount) >> 1) & 1)); \
out = ((out << 2) & tmp) ^ (out & ~tmp); \
tmp = (uint64_t) (-(((shift_amount) >> 2) & 1)); \
out = ((out << 4) & tmp) ^ (out & ~tmp); \
tmp = (uint64_t) (-(((shift_amount) >> 3) & 1)); \
out = ((out << 8) & tmp) ^ (out & ~tmp); \
tmp = (uint64_t) (-(((shift_amount) >> 4) & 1)); \
out = ((out << 16) & tmp) ^ (out & ~tmp); \
if (flag) { \
tmp = (uint64_t) (-(((shift_amount) >> 5) & 1)); \
out = ((out << 32) & tmp) ^ (out & ~tmp); \
} \
} while (0)

#else

/**
 * Constant-time 64-bit left shift of 1. Use if platform's left shift with
 * variable amount is constant-time.
 *
 * @param shift_amount the number of bits to shift the value 1 to the left
 * @param flag flag to indicate the shift amount can be >= 32 (ignored)
 * @return 1 << shift_amount
 */
#define constant_time_shift_1_left64(out, shift_amount, flag) out = (1llu << (shift_amount))

#endif //SHIFT_LEFT64_CONSTANT_TIME



#if (defined(CM_CT) || (defined(CM_CACHE) && PARAMS_K!=1))

#if defined(CM_CT)
#define forCONDITION i < PARAMS_HMAX
#else // CM_CACHE
#define forCONDITION h < 0
#endif

//#if PARAMS_K !=1 // non-ring
//#define drbgINIT    drbg16(x, XSIZE);
//#define drbgEXTRACT drbg16_customization(x, XSIZE);
//#else // ring
//#define drbgINIT    drbg_init(seed);
//#define drbgEXTRACT drbg_init_customization(seed, larray, custom_len);
//#endif

#ifndef  AVX2

int check_and_set(uint64_t secret_vector_64[2][CTSECRETVECTOR64_4], uint16_t x, int h) {
    
    uint64_t a, b, c, t, tt = 0;
    size_t j;
    
    a = 1llu << (x & 0x3F);                //    bit selector
    b = 1llu << (x >> 6);                //    word selector
    a &= (uint64_t)(((int64_t) h) >> 63);            //    set a to zero if h >= 0
    for (j = 0; j < CTSECRETVECTOR64; j++) {
        t = (-(b & 1llu)) & a;            //    bit selector
        // secret_vector[0] encodes the +1, secret_vector[1] encodes the -1
        t &= ~(secret_vector_64[0][j] | secret_vector_64[1][j]); // empty?
        c = -((uint64_t) (h & 1));
        secret_vector_64[1][j] |=  c & t; //set if -1
        secret_vector_64[0][j] |= (~c) & t; //    set if 1
        tt |= t;
        b >>= 1;                        //    b & 1 == 1 when j == x >> 6
    }
    tt |= tt >> 1;                    //    tt == 0 ? 0 : 1
    tt = (tt^(-tt)) >> 63;
 
    return (int)tt;                         //    optional increment
}

#else

static const uint64_t VECM[4] =
{ 1L, 2L, 4L, 8L };

int check_and_set( uint64_t secret_vector_64[2][CTSECRETVECTOR64_4], uint16_t x, int h) {
    
    size_t j;
    register __m256i vec0 = _mm256_setzero_si256();
    register __m256i vec1 = _mm256_set1_epi64x(1L);
    register __m256i veca = _mm256_slli_epi64(vec1, x & 0x3F); // low address part
    register __m256i vecb = _mm256_slli_epi64(vec1, x >> 6  ); // high address part
    register __m256i vecm = _mm256_loadu_si256((const __m256i*) VECM);

    veca = _mm256_and_si256(veca, _mm256_cmpgt_epi64(vec0, _mm256_set1_epi64x((int64_t)(h))));  //    set a to zero if h >= 0

    register __m256i vect, vecaux;
    register __m256i vectt = _mm256_setzero_si256();
    
    for (j = 0; j < CTSECRETVECTOR64_4; j+=4) {
        vect = _mm256_andnot_si256(_mm256_cmpeq_epi64(_mm256_and_si256(vecb, vecm), vec0), veca); //    bit selector
        vecaux = _mm256_or_si256(_mm256_loadu_si256((__m256i*) &secret_vector_64[0][j]), _mm256_loadu_si256((__m256i*) &secret_vector_64[1][j]) ); // empty?
        vect = _mm256_and_si256(vect,_mm256_xor_si256(vecaux, _mm256_set1_epi32(-1)));
        vecaux = _mm256_set1_epi64x(-((int64_t) (h & 1)));
        _mm256_storeu_si256((__m256i*) &secret_vector_64[1][j], _mm256_or_si256(_mm256_loadu_si256((__m256i*) &secret_vector_64[1][j]),_mm256_and_si256(vecaux, vect))); //set if -1
        vecaux =  _mm256_xor_si256(vecaux, _mm256_set1_epi32(-1));
        _mm256_storeu_si256((__m256i*) &secret_vector_64[0][j], _mm256_or_si256(_mm256_loadu_si256((__m256i*) &secret_vector_64[0][j]),_mm256_and_si256(vecaux, vect))); //    set if 1
        vectt = _mm256_or_si256(vectt, vect);  // store change
        vecb = _mm256_srli_epi64( vecb, 4 ); // Next 4 bits.
    }
    return (int)(~_mm256_testz_si256(vectt, vectt))&0x1; // tt == 0 ? 0 : 1
}

#endif


void create_secret_vector_internal(tern_secret secret_vector, const uint8_t *seed, uint64_t l, uint64_t custom_len){
    
    int h;
    size_t i;

    uint64_t secret_vector_64[2][CTSECRETVECTOR64_4] = {{0}};
    
    uint16_t x[PARAMS_XSIZE];
    uint16_t x_count = PARAMS_XSIZE - 1;
    
    uint8_t larray[custom_len];
    for  (i = 0 ; i < custom_len; i++){ larray[i] = (l >> (i*8)) & (0xFF);}
    drbg_init_customization(seed, larray, custom_len);
    
    //    mark >=d slots as occupied (uniform sampling)
#if (PARAMS_D & 0x3F) != 0
    secret_vector_64[0][CTSECRETVECTOR64 - 1] = (~0llu) << (PARAMS_D & 0x3F);
#endif
    
    h = -PARAMS_H;                            //    dummy rounds once h reaches 0
    
    for (i = 0; forCONDITION; i++) {
    
        x_count++;
        if (x_count == PARAMS_XSIZE) {
            drbg16_customization(x, PARAMS_XSIZE);
            x_count = 0;
        }
        x[i & PARAMS_XMASK] /= PARAMS_RS_DIV;                    //    no uniform rejection here
        
        h += check_and_set(secret_vector_64, x[i & PARAMS_XMASK], h);
    }
    
    for (i = 0; i < PARAMS_D; i++) {
        secret_vector[i] = (int16_t) (((secret_vector_64[0][i >> 6] >> (i & 0x3F)) & 1)
                                   -  ((secret_vector_64[1][i >> 6] >> (i & 0x3F)) & 1));
    }
    
    DEBUG_PRINT(
        print_sage_u_vector("Secret key vector (full representation)", (uint16_t *) secret_vector, PARAMS_D);
    )
}

#else  //  !(defined(CM_CT) || (defined(CM_CACHE) && PARAMS_K!=1))


#ifndef  AVX2

int probe_cm(uint64_t *v, const uint16_t x) {
    int i;
    uint64_t a, b, c, y, z;
    // construct the selector
    constant_time_shift_1_left64(y, x & 0x3F, 1); // low bits of index
    constant_time_shift_1_left64(z, x >> 6, 0); // high bits of index
    
    c = 0;
    for (i = 0; i < CTSECRETVECTOR64; i++) { // always scan through all
        a = v[i];
        b = a | (y & (-(z & 1))); // set bit if not occupied.
        c |= a ^ b; // If change, mask.
        v[i] = b; // update value of v[i]
        z >>= 1;
    }
    // final comparison doesn't need to be constant time
    return c == 0; // return true if was occupied before
}

#else

static const uint64_t VECM[4] =
{ 1L, 2L, 4L, 8L };

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
    
    for (int i = 0; i < CTSECRETVECTOR64_4; i+=4) {
        veca = _mm256_loadu_si256((__m256i*) &v[i]);
        vecb = _mm256_andnot_si256(_mm256_cmpeq_epi64(_mm256_and_si256(vech, vecm), vec0), vecl); // Bit position.
        vecb = _mm256_or_si256(veca, vecb);
        vecc = _mm256_or_si256(vecc, _mm256_xor_si256( veca, vecb )); // Accumulate change.
        _mm256_storeu_si256((__m256i*) &v[i], vecb); // Update value of add[i].
        vech = _mm256_srli_epi64( vech, 4 ); // Next 4 bits.
    }
    return _mm256_testz_si256(vecc, vecc); // return false if any change
}

#endif // AVX2

void create_secret_vector_internal(tern_secret secret_vector, const uint8_t *seed, uint64_t l, uint64_t custom_len) {
    size_t i;
    uint16_t x;
    
#if defined(CM_CACHE)
    uint64_t v[CTSECRETVECTOR64_4] = {0};
#else
    uint8_t v[PARAMS_D] = {0};
#endif
    
    uint8_t larray[custom_len];
    for  (i = 0 ; i < custom_len; i++){ larray[i] = (l >> (i*8)) & (0xFF);}
    
    drbg_init_customization(seed, larray, custom_len);
    
    for (i = 0; i < PARAMS_H; i++) {
        do {
            do {
                one_uint16_t_customization(x);
            } while (x >= PARAMS_RS_LIM);
            x /= PARAMS_RS_DIV;
            
#if defined(CM_CACHE)
        } while (probe_cm(v, x));
#else
        } while (v[x]);
        v[x] = 1;
#endif
        secret_vector[i >> 1][i & 1] = x; // addition / subtract index
    }

    DEBUG_PRINT(
         print_sage_u_vector_matrix("Secret key vector (index representation)", secret_vector, PARAMS_H/2, 2, 1);
    )
}

#endif


void create_secret_vector(tern_secret secret_vector, const uint8_t *seed){
    create_secret_vector_internal(secret_vector, seed, 0, 0);
}

void create_secret_matrix_s_t(tern_secret_s secret_vector, const uint8_t *seed) {
    
    uint64_t l;
    
    uint64_t custom_len = 0;
    if (PARAMS_N_BAR > 1){custom_len = PARAMS_CUSTOM_LEN;}
    
    for (l = 0; l < PARAMS_N_BAR; l++) {
        create_secret_vector_internal((tern_coef_type *)(&secret_vector[l]), seed, l, custom_len);
    }
}

void create_secret_matrix_r_t(tern_secret_r secret_vector, const uint8_t *seed) {
    
    uint64_t l;
    
    uint64_t custom_len = 0;
    if (PARAMS_M_BAR > 1){custom_len = PARAMS_CUSTOM_LEN;}
    
    for (l = 0; l < PARAMS_M_BAR; l++) {
        create_secret_vector_internal((tern_coef_type *)(&secret_vector[l]), seed, l, custom_len);
    }
}
