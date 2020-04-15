#ifndef _SHAKING_
#define _SHAKING_

//	Copyright (c) 2020, PQShield Ltd and Koninklijke Philips N.V., 
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

typedef CContext TupleHashContext;

typedef struct tupleHash_Instance{
    ContextInstance ccontext;
    uint16_t outputBitLen;
} ttupleHash_Instance;

typedef struct tupleHash_Instance *TupleHash_Instance;

typedef struct tupleHash_Instance *THContextInstance;

#else // !STANDALONE

#include <libkeccak.a.headers/KeccakHash.h>
#include <libkeccak.a.headers/SP800-185.h>

typedef Keccak_HashInstance ContextInstance; 
typedef Keccak_HashInstance *Context; 
typedef cSHAKE_Instance CContextInstance; 
typedef cSHAKE_Instance *CContext;

typedef TupleHash_Instance ttupleHash_Instance;
typedef TupleHash_Instance *THContextInstance;



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
	( CContext context,
     const uint8_t *input, size_t inputLength,
     const uint8_t *functionName, size_t functionnameLength,
	 const uint8_t *customization, size_t customizationLength
     Parameters );

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
     uint32_t inputLength,
     const uint8_t *functionName, size_t functionnameLength ,
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

//// tuplehash 

extern void r5_tuple_hash // tuple_hash
    ( uint8_t *output, uint32_t outputLen,
      const uint8_t *domain, uint8_t domainLen,
      const uint8_t *first, uint16_t firstLen,
      const uint8_t *second, uint32_t secondLen,
      uint8_t numberOfElements
      Parameters );

extern void r5_tuple_hash16
    ( uint16_t *output, uint32_t outputLen,
      const uint8_t *domain, uint8_t domainLen,
      const uint8_t *first, uint16_t firstLen,
      const uint8_t *second, uint32_t secondLen,
      uint8_t numberOfElements
      Parameters);

extern void r5_tuple_hash_xof
( uint8_t *output, uint32_t outputLen,
  const uint8_t *domain, uint8_t domainLen,
  const uint8_t *first, uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements
  Parameters);

extern void r5_tuple_hash_xof16
 (uint16_t *output, uint32_t outputLen,
  const uint8_t *domain, uint8_t domainLen,
  const uint8_t *first, uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements
  Parameters);

extern void r5_tuple_hash_input
(THContextInstance tinstance,
  const uint8_t *domain, const uint8_t domainLen,
  const uint8_t *first, const uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements,
  uint32_t outputLenBytes
  Parameters );

extern void r5_tuple_hash_xof_squeeze16 
( uint16_t *out, uint32_t outputLen,
 THContextInstance tinstance
 Parameters );

#ifdef AVX2SHAKE

void r5_tuple_hash16_4x
(uint16_t *output0,
 uint16_t *output1,
 uint16_t *output2,
 uint16_t *output3,
 uint32_t outputLen,
 const uint8_t *domain0,
 const uint8_t *domain1,
 const uint8_t *domain2,
 const uint8_t *domain3,
 uint8_t domainLen,
 const uint8_t *first0,
 const uint8_t *first1,
 const uint8_t *first2,
 const uint8_t *first3,
 uint16_t firstLen,
 const uint8_t *second0,
 const uint8_t *second1,
 const uint8_t *second2,
 const uint8_t *second3,
 uint32_t secondLen,
 uint8_t numberOfElements
 Parameters );

void r5_tuple_hash_xof16_4x
(uint16_t *output0,
 uint16_t *output1,
 uint16_t *output2,
 uint16_t *output3,
 uint32_t outputLen,
 const uint8_t *domain0,
 const uint8_t *domain1,
 const uint8_t *domain2,
 const uint8_t *domain3,
 uint8_t domainLen,
 const uint8_t *first0,
 const uint8_t *first1,
 const uint8_t *first2,
 const uint8_t *first3,
 uint16_t firstLen,
 const uint8_t *second0,
 const uint8_t *second1,
 const uint8_t *second2,
 const uint8_t *second3,
 uint32_t secondLen,
 uint8_t numberOfElements
 Parameters );

extern void r5_tuple_hash_xof_squeeze16_4x // tuple_hash_xof_squeeze
(
 uint16_t *output0,
 uint16_t *output1,
 uint16_t *output2,
 uint16_t *output3,
 uint32_t outputLen,
 TupleHash_Instance THContext
 Parameters );

extern void r5_tuple_hash_input_4x // tuple_hash_xof_input
(TupleHash_Instance THContext,
 const uint8_t *domain0,
 const uint8_t *domain1,
 const uint8_t *domain2,
 const uint8_t *domain3,
 uint8_t domainLen,
 const uint8_t *first0,
 const uint8_t *first1,
 const uint8_t *first2,
 const uint8_t *first3,
 uint16_t firstLen,
 const uint8_t *second0,
 const uint8_t *second1,
 const uint8_t *second2,
 const uint8_t *second3,
 uint32_t secondLen,
 uint8_t numberOfElements,
 uint32_t outputLenBytes
 Parameters );
#endif

#endif /* _SHAKING_ */


