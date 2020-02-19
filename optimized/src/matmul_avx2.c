/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 *
 */

// Fast matrix arithmetic with AVX2 instructions

#include "matmul.h"

#if PARAMS_K !=1 && defined(AVX2)

#include "misc.h"
#include "drbg.h"
#include "little_endian.h"

#include <immintrin.h>
#include <string.h>

//  This allows working on blocks of data < PARAMS_D.
#define BLOCK_SIZE_COL PARAMS_D
//  If > 1, this allows using multiple secrets in parallel.
#define BLOCK_SIZE_ROW 1
// Number of elements for which the operations are performed in parallel.
#define BLOCK_AVX 16


#define PROBEVEC64  ((PARAMS_D + 63) / 64)



// Matrix ////////////////////////////////////////////////////////////////////////////////////////////////////
// B       K                 N                     K
//    . . . ... .       . . . . ... .        . . . ... .
//    . . . ... .       . . . . ... .        . . . ... .
// L  . . . ... .   ==  . . . . ... .   * N  . . . ... . where B(i,j) = inner( N[.][i], K[i][.] )
//                                           . . . ... .
//    . . . ... .       . . . . ... .
//

#if PARAMS_D % BLOCK_AVX != 0
static const int16_t mask[16] __attribute__ ((aligned(32))) =
{ ((int16_t) ( 0))
    , (int16_t) ( BLOCK_SIZE_COL - 15 >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 14 >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 13 >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 12 >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 11 >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 10 >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 9  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 8  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 7  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 6  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 5  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 4  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 3  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , (int16_t) ( BLOCK_SIZE_COL - 2  >= BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX) ? -1 : 0 )
    , ((int16_t) (-1))
} ;
#endif

#define vGet(X)   _mm256_loadu_si256((__m256i*)(X))
#define vPut(X,Y) _mm256_storeu_si256((__m256i*)(X),Y)
#define vSet(X)   _mm256_set1_epi16(X)
#define vMul(X,Y) _mm256_mullo_epi16(X,Y)
#define vAdd(X,Y) _mm256_add_epi16(X,Y)

inline modq_t vSum(__m256i v) __attribute__ ((always_inline));
modq_t vSum( __m256i v ) {
    v = _mm256_hadd_epi16(v, v);
    v = _mm256_hadd_epi16(v, v);
    v = _mm256_hadd_epi16(v, v);
    return (modq_t) (_mm256_extract_epi16(v, 0) + _mm256_extract_epi16(v, 8));
}

// precondition: length vector >= BLOCK_AVX

inline void inner1(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner1 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i a256 = vMul(vGet(vx), vGet(vy));
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        a256 = vAdd(a256, vMul(vGet(vx + c), vGet(vy + c)));
    }
#if PARAMS_D % BLOCK_AVX != 0
    a256 = vAdd(a256, vMul(vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256, vGet(vy + BLOCK_SIZE_COL - BLOCK_AVX)));
#endif
    *a = vSum(a256);
}

// inner1 parallel 8 reg

#define aci(I,X) register __m256i a256_##I = vMul(X, vGet(vy + I * PARAMS_D))
#define aca(I,X) a256_##I  = vAdd(a256_##I,  vMul(X, vGet(vy + I * PARAMS_D + c)))
#define acm(I,X) a256_##I  = vAdd(a256_##I,  vMul(X, vGet(vy + I * PARAMS_D + BLOCK_SIZE_COL - BLOCK_AVX)))
#define acs(I,A) A[I] = vSum(a256_##I)

#define a256I1(X) aci(0,X)
#define a256A1(X) aca(0,X)
#define a256M1(X) acm(0,X)
#define a256S1(A) acs(0,A)

#define a256I2(X) a256I1(X); aci(1,X);
#define a256A2(X) a256A1(X); aca(1,X);
#define a256M2(X) a256M1(X); acm(1,X);
#define a256S2(A) a256S1(A); acs(1,A);

#define a256I3(X) a256I2(X); aci(2,X);
#define a256A3(X) a256A2(X); aca(2,X);
#define a256M3(X) a256M2(X); acm(2,X);
#define a256S3(A) a256S2(A); acs(2,A);

#define a256I4(X) a256I3(X); aci(3,X);
#define a256A4(X) a256A3(X); aca(3,X);
#define a256M4(X) a256M3(X); acm(3,X);
#define a256S4(A) a256S3(A); acs(3,A);

#define a256I5(X) a256I4(X); aci(4,X);
#define a256A5(X) a256A4(X); aca(4,X);
#define a256M5(X) a256M4(X); acm(4,X);
#define a256S5(A) a256S4(A); acs(4,A);

#define a256I6(X) a256I5(X); aci(5,X);
#define a256A6(X) a256A5(X); aca(5,X);
#define a256M6(X) a256M5(X); acm(5,X);
#define a256S6(A) a256S5(A); acs(5,A);

#define a256I7(X) a256I6(X); aci(6,X);
#define a256A7(X) a256A6(X); aca(6,X);
#define a256M7(X) a256M6(X); acm(6,X);
#define a256S7(A) a256S6(A); acs(6,A);

#define a256I8(X) a256I7(X); aci(7,X);
#define a256A8(X) a256A7(X); aca(7,X);
#define a256M8(X) a256M7(X); acm(7,X);
#define a256S8(A) a256S7(A); acs(7,A);

inline void inner2(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner2 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I2(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A2(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M2(xx);
#endif
    a256S2(a);
}

inline void inner3(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner3 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I3(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A3(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M3(xx);
#endif
    a256S3(a);
}

inline void inner4(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner4 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I4(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A4(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M4(xx);
#endif
    a256S4(a);
}

inline void inner5(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner5 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I5(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A5(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M5(xx);
#endif
    a256S5(a);
}

inline void inner6(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner6 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I6(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A6(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M6(xx);
#endif
    a256S6(a);
}

inline void inner7(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner7 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I7(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A7(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M7(xx);
#endif
    a256S7(a);
}

// inline void inner8(modq_t *vx, int16_t *vy, modq_t *a) __attribute__ ((always_inline));
void inner8 ( modq_t *vx, int16_t *vy, modq_t *a ) {
    size_t c;
    register __m256i xx = vGet(vx); a256I8(xx);
#if PARAMS_D % BLOCK_AVX != 0
    register __m256i m256 = vGet(&mask);
#endif
    for (c = BLOCK_AVX; c < BLOCK_AVX * (PARAMS_D / BLOCK_AVX); c += BLOCK_AVX) {
        xx = vGet(vx+c); a256A8(xx);
    }
#if PARAMS_D % BLOCK_AVX != 0
    xx = vGet(vx + BLOCK_SIZE_COL - BLOCK_AVX) & m256; a256M8(xx);
#endif
    a256S8(a);
}

// Matrix a can be permted !

#if PARAMS_TAU == 0
#define matrix(A) A[PARAMS_D][PARAMS_D]
#define access(A,R) A[R]

#elif PARAMS_TAU == 1
#define matrix(A) A[2 * PARAMS_D * PARAMS_D], uint32_t a_permutation[PARAMS_D]
#define access(A,R) &A[a_permutation[R]]

#elif PARAMS_TAU == 2
#define matrix(A) A[PARAMS_TAU2_LEN + PARAMS_D], uint16_t a_permutation[PARAMS_D]
#define access(A,R) &A[a_permutation[R]]
#endif

#if   ( PARAMS_N_BAR % 8 == 1 )
#define parallel 1
#elif ( PARAMS_N_BAR % 8 == 2 )
#define parallel 2
#elif ( PARAMS_N_BAR % 8 == 3 )
#define parallel 3
#elif ( PARAMS_N_BAR % 8 == 4 )
#define parallel 4
#elif ( PARAMS_N_BAR % 8 == 5 )
#define parallel 5
#elif ( PARAMS_N_BAR % 8 == 6 )
#define parallel 6
#elif ( PARAMS_N_BAR % 8 == 7 )
#define parallel 7
#endif
#define cat(X,Y) X##Y
#define Inner(X) cat(inner,X)

//
// B = A * S
//
void matmul_as_q(modq_t d[PARAMS_D][PARAMS_N_BAR], modq_t matrix(a), tern_secret_s secret_vector){
    
    size_t r, l;
    for (r = 0; r < PARAMS_D; r++) {
        for (l = 0; l < (PARAMS_N_BAR/8) * 8; l+=8)
        Inner(8)(access(a,r), secret_vector[l], &d[r][l]);
#if ( PARAMS_N_BAR % 8 != 0 )
        Inner(parallel)(access(a,r), secret_vector[(PARAMS_N_BAR/8) * 8], &d[r][(PARAMS_N_BAR/8) * 8]);
#endif
    }
}

void matmul_rta_q(modq_t d[PARAMS_M_BAR][PARAMS_D], modq_t matrix(a), tern_secret_r secret_vector){
    
    size_t r, c, l;
    modq_t * row __attribute__ ((aligned(32)));
    
    
    __m256i accum[PARAMS_M_BAR * PARAMS_D / 16] __attribute__ ((aligned(32)));
    for (l = 0; l < PARAMS_M_BAR; l++) {
        for (c = 0; c < 16 * (PARAMS_D / 16); c += 16) {
            accum[(l * BLOCK_SIZE_COL + c) >> 4] = _mm256_setzero_si256();
        }
    }
    
    memset(d, 0, PARAMS_M_BAR * PARAMS_D * sizeof (modq_t));
    for (l = 0; l < PARAMS_D ; l++) {
        row = access(a,l);
        for (c = 0; c < (PARAMS_D/16) ; c+=1)
        for (r = 0; r < PARAMS_M_BAR; r++)
        {
            accum[r * BLOCK_SIZE_COL / BLOCK_AVX + c] = vAdd( accum[r * BLOCK_SIZE_COL / BLOCK_AVX + c], vMul(vSet(secret_vector[r][l]), vGet(&row[c<<4])));
            //vPut(&d[r][c], vAdd(vGet(&d[r][c]), vMul(vSet(r_t[r][l]), vGet(&row[c<<4]))));
        }
#if PARAMS_D % 16 != 0
        for (c = (PARAMS_D/16)*16 ;  c < PARAMS_D ;c++)
        for (r = 0; r < PARAMS_M_BAR; r++)
        d[r][c] +=  secret_vector[r][l] * row[c];
    }
#endif
    for (l = 0; l < PARAMS_M_BAR; l++) {
        for (c = 0; c < BLOCK_AVX * (BLOCK_SIZE_COL / BLOCK_AVX); c += BLOCK_AVX) {
            _mm256_storeu_si256((__m256i *) &(d[l][c]), accum[(l * BLOCK_SIZE_COL + c) >> 4]);
        }
    }
}

//
// X' = S^T * U
//
// assumption: PARAMS_MU <= PARAMS_N_BAR * PARAMS_N_BAR
void matmul_stu_p(modp_t d[PARAMS_MU], modp_t u_t[PARAMS_M_BAR][PARAMS_D], tern_secret_s secret_vector){
    
    size_t l, j;
    size_t index = 0;
    for (l = 0; l < PARAMS_N_BAR && index < PARAMS_MU; l++)
    for (j = 0; j < PARAMS_M_BAR && index < PARAMS_MU; j++)
    Inner(1)(u_t[j], secret_vector[l], &d[index++]);
}
#endif /* PARAMS_K !=1 && defined(AVX2) */
