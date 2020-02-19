#ifndef _AES_DRBG_H_
#define _AES_DRBG_H_

/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include <stdint.h>
#include <openssl/evp.h>
#include "chooseparameters.h"
#include "shaking.h"
#include "r5_hash.h"
#include "misc.h"


//	Types:

typedef struct contextAESInstance *AESContext;
typedef struct contextAESInstance
{
	EVP_CIPHER_CTX *aes_ctx; // The AES cipher context 
	uint8_t     state[16]; // Initial state, always 0    

	uint8_t        *index; // Index to remaining
    uint8_t remaining[16]; // Remaining bytes
} AESContextInstance; 
 
//	Public Interface:

#define initAESdrbg(context) \
	AESContextInstance context = {0} 

extern void produce
	( AESContext context
	, uint8_t *output, size_t outputLength );

extern void produce16
	( AESContext context
	, uint16_t *output, size_t outputLength );

extern void consume
	( AESContext context, const uint8_t *seed Parameters);

extern void generate
	( uint8_t *output, size_t outputLength
	, const uint8_t *seed Parameters);

extern void generate16
	( uint16_t *output, size_t outputLength
	, const uint8_t *seed Parameters);

extern void cconsume
	( AESContext context, const uint8_t *seed
	, const uint8_t *customization, size_t customizationLength Parameters);

extern void cgenerate
	( uint8_t *output, size_t outputLength
	, const uint8_t *seed
	, const uint8_t *customization, size_t customizationLength Parameters);

extern void cgenerate16
	( uint16_t *output, size_t outputLength
	, const uint8_t *seed
	, const uint8_t *customization, size_t customizationLength Parameters);

#define freeAESContext(X) EVP_CIPHER_CTX_free((X).aes_ctx);

#endif /* _EAS_DRBG_H_ */


