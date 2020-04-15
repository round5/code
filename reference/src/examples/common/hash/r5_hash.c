/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Definition of the hash function as used within Round5.
 */

#include "r5_hash.h"

extern void hash
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters );

extern void hash_customization 
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters );

