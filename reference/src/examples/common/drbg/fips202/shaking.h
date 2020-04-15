#ifndef _SHAKING_
#define _SHAKING_

//	Copyright (c) 2019, PQShield Ltd and Koninklijke Philips N.V., 
//      Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Importing, build upon:

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "chooseparameters.h"


#ifdef STANDALONE

#ifdef AVX2
#define AVX2SHAKE
#endif


#include "keccakf1600.h"

#ifdef AVX2SHAKE
#include <immintrin.h>
#include "KeccakP-1600-times4-SnP.h"
#endif



//	Types:

typedef struct contextInstance *Context;

#ifdef AVX2SHAKE
typedef struct contextInstance{
    uint64_t         state[25];  // each element, contains 4 uint64_t state variables
    __m256i          state_4x[25];  // each element, contains 4 uint64_t state variables
    uint8_t          *index; // pointer to first remaining.
    uint8_t          *index0; // pointer to first remaining.
    uint8_t          *index1; // pointer to first remaining.
    uint8_t          *index2; // pointer to first remaining.
    uint8_t          *index3; // pointer to first remaining.
    uint8_t          remaining[168];  // maxremaining bytes
    uint8_t          remaining0[168];  // maxremaining bytes
    uint8_t          remaining1[168];  // maxremaining bytes
    uint8_t          remaining2[168];  // maxremaining bytes
    uint8_t          remaining3[168];  // maxremaining bytes
} ContextInstance;
#else
typedef struct contextInstance{
	uint64_t      state[25];      
	uint8_t          *index; // pointer to first remaining
	uint8_t remaining[168];  // maxremaining bytes
} ContextInstance; 
#endif

typedef struct contextInstance *CContext;
typedef ContextInstance CContextInstance;

#else
//	Importing, build upon:

#include <libkeccak.a.headers/KeccakHash.h>
#include <libkeccak.a.headers/SP800-185.h>


//	Types:

typedef Keccak_HashInstance ContextInstance; 
typedef Keccak_HashInstance *Context; 
typedef cSHAKE_Instance CContextInstance; 
typedef cSHAKE_Instance *CContext;

#endif
//	Public Interface: 

extern void r5_xof_input  
	( Context context
	, const uint8_t *input, size_t inputLength Parameters );

extern void r5_xof_squeeze
   	( Context context
	, uint8_t *output, size_t outputLength Parameters );

extern void r5_xof_squeeze16
	( Context context
	, uint16_t *output, size_t outputLength Parameters );

extern void r5_xof // shake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters );

extern void r5_xof16 // shake16
	( uint16_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters );

// cshake:

extern void r5_xof_s_input 
	( CContext context
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters );

extern void r5_xof_s_squeeze
   	( CContext context
	, uint8_t *output, size_t outputLength Parameters );

extern void r5_xof_s_squeeze16
	( CContext context
	, uint16_t *output, size_t outputLength Parameters );

extern void r5_xof_s // cshake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters );

extern void r5_xof_s16 // cshake16
	( uint16_t *output, size_t outputLength
	, const uint8_t *input,  size_t inputLength
	, const uint8_t *customization,  size_t customizationLength Parameters );

#ifdef AVX2SHAKE
extern void r5_xof_s_input_4x // custom init absorb finalize
    (CContext context,
     const uint8_t *input0, const uint8_t *input1, const uint8_t *input2, const uint8_t *input3,
     size_t inputLength,
     const uint8_t *customization0, const uint8_t *customization1, const uint8_t *customization2, const uint8_t *customization3,
     size_t customizationLength Parameters );

extern void r5_xof_s_squeeze16_4x
    (CContext context,
     uint16_t *output0, uint16_t *output1, uint16_t *output2, uint16_t *output3,
     size_t outputLength Parameters );


extern void r5_xof_s16_4x // cshake16
    ( uint16_t *output0, uint16_t *output1, uint16_t *output2, uint16_t *output3, size_t outputLength
     , const uint8_t *input0, const uint8_t *input1, const uint8_t *input2, const uint8_t *input3, size_t inputLength
     , const uint8_t *customization0, const uint8_t *customization1, const uint8_t *customization2, const uint8_t *customization3, size_t customizationLength Parameters );
#endif

#endif /* _SHAKING_ */


