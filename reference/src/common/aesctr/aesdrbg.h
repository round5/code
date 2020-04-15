#ifndef _AES_DRBG_H_
#define _AES_DRBG_H_

/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include <stdint.h>
#include <openssl/evp.h>
#include "chooseparameters.h"
#include "f202sp800185.h"
#include "r5_hash.h"
#include "misc.h"

typedef struct contextAESInstance *AESContext;
typedef struct contextAESInstance
{
	EVP_CIPHER_CTX *aes_ctx; // The AES cipher context 
	uint8_t     state[16]; // Initial state, always 0    

	uint8_t        *index; // Index to remaining
    uint8_t remaining[16]; // Remaining bytes
} AESContextInstance; 

extern void aesctr16(uint16_t *output, size_t outputLength,
                        const uint8_t *domain, uint8_t domainLen,
                        const uint8_t *first, uint16_t firstLen,
                        const uint8_t *second, uint32_t secondLen
                        Parameters);

#endif /* _EAS_DRBG_H_ */


