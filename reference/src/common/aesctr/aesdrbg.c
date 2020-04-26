/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include "aesdrbg.h"

static void AESinCtrModeConfig
	( AESContext context, const uint8_t *key Parameters)
{ 
	context->aes_ctx = EVP_CIPHER_CTX_new();
	if ( !context->aes_ctx ) { 
		DEBUG_ERROR("Error: failed to create encryption context of the DRBG.\n"); 
		abort(); 
	}

	const EVP_CIPHER *EVP_aes_ctr =   
		( ( PARAMS_KAPPA_BYTES <= 16 ) 
		? EVP_aes_128_ctr() 
		: ( ( PARAMS_KAPPA_BYTES == 24 ) 
		  ? EVP_aes_192_ctr() 
		  : EVP_aes_256_ctr() 
		) ) ;

	if (EVP_EncryptInit_ex(context->aes_ctx, EVP_aes_ctr, NULL, key, NULL) != 1) { 
		DEBUG_ERROR("Error: failed to initialize encryption context for the DRBG.\n"); 
		abort(); 
	}
	context-> index = &context->remaining[16];
}

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#define address d=-d
#else
#define address 0
#endif

void AESCTRGen16
	( AESContext context
	, uint16_t *out, size_t outputLength )
{
	uint8_t *buffer = context->index;
	size_t no = (size_t) ((&context->remaining[16]) - buffer);
	uint8_t *output = ((uint8_t *) (out));
	outputLength *= 2;

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	int d = -1;
#endif

	while( outputLength >= no ) {
		while( buffer < &context->remaining[16] ) {
			output[address] = *buffer++; 
			output++; 
		}
		outputLength -= no;

		int len;
		if ( EVP_EncryptUpdate(context->aes_ctx, context->remaining, &len, context->state, 16) != 1) {
			DEBUG_ERROR("Error: failed to generate deterministic random data.\n");
			abort();
		}
		no = 16;
                buffer = context->remaining;
	}
	for ( size_t i = 0; i < outputLength; i++ ) {
		output[address] = *buffer++; 
		output++; 
	}
	context->index = buffer;
}

void AESCTRInit
    ( AESContext context,
     const uint8_t *domain, uint8_t domainLen,
     const uint8_t *first, uint16_t firstLen,
     const uint8_t *second, uint32_t secondLen
     Parameters)
{
    uint8_t key[PARAMS_KAPPA_BYTES] = {0};
    r5_tuple_hash(key, PARAMS_KAPPA_BYTES, domain, domainLen, first, PARAMS_KAPPA_BYTES, second, secondLen, 3 Params);
    AESinCtrModeConfig(context, key Params);
}


void aesctr16
    (uint16_t *output, size_t outputLength,
     const uint8_t *domain, uint8_t domainLen,
     const uint8_t *first, uint16_t firstLen,
     const uint8_t *second, uint32_t secondLen
     Parameters)
{
    AESContextInstance context = {0} ;
    AESCTRInit(&context, domain, domainLen, first, firstLen, second, secondLen Params);
    AESCTRGen16(&context, output, outputLength);
    EVP_CIPHER_CTX_free((context).aes_ctx);
}


