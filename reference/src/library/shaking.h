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
//	Types:
#include "keccakf1600.h"

typedef struct contextInstance *Context;
typedef struct contextInstance{
	uint64_t      state[25];      
	uint8_t          *index; // pointer to first remaining
	uint8_t remaining[168];  // maxremaining bytes
} ContextInstance; 

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

#endif /* _SHAKING_ */


