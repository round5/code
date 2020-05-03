//	Copyright (c) 2020, PQShield Ltd and Koninklijke Philips N.V.,
//      Markku-Juhani O. Saarinen <mjos@pqshield.com>


#include "f202sp800185.h"

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#define address d=-d
#else
#define address 0
#endif


#ifdef STANDALONE

#ifdef AVX2
#define AVX2SHAKE
#endif

//	Importing, build upon:

#include <assert.h>
#include <string.h>

#include "r5_memory.h"


#include "keccakf1600.h"

#ifdef AVX2SHAKE

#include <immintrin.h>
#include "KeccakP-1600-times4-SnP.h"

/* Use implementation from the Keccak Code Package */
extern void KeccakP1600times4_PermuteAll_24rounds(void *state);
#define KeccakF1600_StatePermute_4x KeccakP1600times4_PermuteAll_24rounds

static void keccak_absorb_4x
( Context context,
 const uint8_t *input0,
 const uint8_t *input1,
 const uint8_t *input2,
 const uint8_t *input3,
 size_t inputLength,
 uint8_t pad
 Parameters )
{
    while ( inputLength >= RATE ) {

        KeccakF1600_StateXORBytes_4x(context->state_4x, input0, input1, input2, input3 Params);

        KeccakF1600_StatePermute_4x(context->state_4x);
        
        inputLength -= RATE;

        input0 += RATE;
        input1 += RATE;
        input2 += RATE;
        input3 += RATE;
    }

    memcpy(context->remaining0, input0, inputLength);
    memcpy(context->remaining1, input1, inputLength);
    memcpy(context->remaining2, input2, inputLength);
    memcpy(context->remaining3, input3, inputLength);

    context->remaining0[inputLength] = pad;
    context->remaining1[inputLength] = pad;
    context->remaining2[inputLength] = pad;
    context->remaining3[inputLength] = pad;

    inputLength += 1;

    memset(&context->remaining0[inputLength], 0x00, RATE - inputLength);
    memset(&context->remaining1[inputLength], 0x00, RATE - inputLength);
    memset(&context->remaining2[inputLength], 0x00, RATE - inputLength);
    memset(&context->remaining3[inputLength], 0x00, RATE - inputLength);

    context->remaining0[RATE - 1] |= 0x80;
    context->remaining1[RATE - 1] |= 0x80;
    context->remaining2[RATE - 1] |= 0x80;
    context->remaining3[RATE - 1] |= 0x80;
    
    KeccakF1600_StateXORBytes_4x(context->state_4x, context->remaining0, context->remaining1, context->remaining2, context->remaining3 Params );
    
    context->index0 = &(context->remaining0[RATE]);
    context->index1 = &(context->remaining1[RATE]);
    context->index2 = &(context->remaining2[RATE]);
    context->index3 = &(context->remaining3[RATE]);

}

static void r5_xof_squeeze16_4x
(Context context,
 uint16_t *out0,
 uint16_t *out1,
 uint16_t *out2,
 uint16_t *out3,
 size_t outputLength
 Parameters)
{
    uint8_t *buffer0 = context->index0;
    uint8_t *buffer1 = context->index1;
    uint8_t *buffer2 = context->index2;
    uint8_t *buffer3 = context->index3;
    
    size_t no0 = (size_t) ((&context->remaining0[RATE]) - buffer0);
    
    uint8_t *output0 = ((uint8_t *) (out0));
    uint8_t *output1 = ((uint8_t *) (out1));
    uint8_t *output2 = ((uint8_t *) (out2));
    uint8_t *output3 = ((uint8_t *) (out3));
    
    outputLength *= 2;
    
    int d = -1;
    
    while( outputLength >= no0 ) {
        while( buffer0 < &context->remaining0[RATE] ) {
            
            output0[address] = *buffer0++;
            output1[address] = *buffer1++;
            output2[address] = *buffer2++;
            output3[address] = *buffer3++;
            
            output0++;
            output1++;
            output2++;
            output3++;
            
        }
        
        outputLength -= no0;
        
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        while( outputLength >= RATE ) {
            KeccakF1600_StatePermute_4x(context->state_4x);
            KeccakF1600_StateExtractBytes_4x(context->state_4x, output0, output1, output2, output3 Params);
            outputLength -= RATE;
            
            output0 += RATE;
            output1 += RATE;
            output2 += RATE;
            output3 += RATE;
        }
#endif
        KeccakF1600_StatePermute_4x(context->state_4x);
        KeccakF1600_StateExtractBytes_4x(context->state_4x, context->remaining0, context->remaining1, context->remaining2, context->remaining3 Params);
        
        no0 = RATE;
        
        buffer0 = context->remaining0;
        buffer1 = context->remaining1;
        buffer2 = context->remaining2;
        buffer3 = context->remaining3;
    }
    
    for ( size_t i = 0; i < outputLength; i++ ) {

        output0[address] = *buffer0++;
        output1[address] = *buffer1++;
        output2[address] = *buffer2++;
        output3[address] = *buffer3++;
        
        output0++;
        output1++;
        output2++;
        output3++;
    }
    
    context->index0 = buffer0;
    context->index1 = buffer1;
    context->index2 = buffer2;
    context->index3 = buffer3;
}

void r5_xof_s_input_4x // custom init absorb finalize
( CContext context,
 const uint8_t *input0,
 const uint8_t *input1,
 const uint8_t *input2,
 const uint8_t *input3,
 uint32_t inputLength,
 const uint8_t *functionName,
 size_t functionnameLength ,
 const uint8_t *customization0,
 const uint8_t *customization1,
 const uint8_t *customization2,
 const uint8_t *customization3,
 size_t customizationLength Parameters )
{
    if ((customizationLength == 0) && (functionnameLength == 0)){
        keccak_absorb_4x(context, input0, input1, input2, input3, inputLength, 0x1F Params);
    } else {
        uint8_t *in0 = context->remaining0;
        uint8_t *in1 = context->remaining1;
        uint8_t *in2 = context->remaining2;
        uint8_t *in3 = context->remaining3;
        
        // bytepad(encode_string(N) || encode_string(S), rate)
        // left encoding of rate. Then string
        *in0++ = 0x01; *in0++ = RATE;
        *in1++ = 0x01; *in1++ = RATE;
        *in2++ = 0x01; *in2++ = RATE;
        *in3++ = 0x01; *in3++ = RATE;
        
        // encode_string(N) = left_encode(N) || N. If N empty, 0x01 || 0x00
        *in0++ = 0x01;
        *in1++ = 0x01;
        *in2++ = 0x01;
        *in3++ = 0x01;
        assert( functionnameLength < 32 );
        *in0++ = (uint8_t) (functionnameLength << 3);
        *in1++ = (uint8_t) (functionnameLength << 3);
        *in2++ = (uint8_t) (functionnameLength << 3);
        *in3++ = (uint8_t) (functionnameLength << 3);
        memcpy(in0, functionName, functionnameLength);
        memcpy(in1, functionName, functionnameLength);
        memcpy(in2, functionName, functionnameLength);
        memcpy(in3, functionName, functionnameLength);
        in0 += functionnameLength;
        in1 += functionnameLength;
        in2 += functionnameLength;
        in3 += functionnameLength;
        
        // encode_string(S) = left_encode(S) || S. If S empty, 0x01 || 0x00
        *in0++ = 0x01;
        *in1++ = 0x01;
        *in2++ = 0x01;
        *in3++ = 0x01;
        assert( customizationLength < 32 );
        *in0++ = (uint8_t) (customizationLength << 3);
        *in1++ = (uint8_t) (customizationLength << 3);
        *in2++ = (uint8_t) (customizationLength << 3);
        *in3++ = (uint8_t) (customizationLength << 3);
        memcpy(in0, customization0, customizationLength);
        memcpy(in1, customization1, customizationLength);
        memcpy(in2, customization2, customizationLength);
        memcpy(in3, customization3, customizationLength);
        
        KeccakF1600_StateXORBytes_4x(context->state_4x, context->remaining0, context->remaining1, context->remaining2, context->remaining3 Params );
        KeccakF1600_StatePermute_4x(context->state_4x);
        
        keccak_absorb_4x(context, input0, input1, input2, input3, inputLength, 0x04 Params );
        
    }
}


void r5_xof_s_squeeze16_4x //cqueeze16_4x
( CContext context,
 uint16_t *output0,
 uint16_t *output1,
 uint16_t *output2,
 uint16_t *output3,
 size_t outputLength
 Parameters )
{
    r5_xof_squeeze16_4x(context, output0, output1, output2, output3, outputLength Params );
}



void r5_tuple_hash_input_4x // tuple_hash_xof_input
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
 Parameters )
{
    // ToDo: this memory overhead goes away by rewriting this function in such a way that
    // the inputs are absorbed into the state
    uint8_t *input0, *input1, *input2, *input3;
    input0 = checked_malloc(14 + domainLen + firstLen + secondLen);
    input1 = checked_malloc(14 + domainLen + firstLen + secondLen);
    input2 = checked_malloc(14 + domainLen + firstLen + secondLen);
    input3 = checked_malloc(14 + domainLen + firstLen + secondLen);
    
    uint8_t *in0 = input0, *in1 = input1,  *in2 = input2, *in3 = input3;
    uint32_t inputLen = 0;
    
    *in0++ = 0x01;
    *in1++ = 0x01;
    *in2++ = 0x01;
    *in3++ = 0x01;
    assert( domainLen < 32 );
    *in0++ = (uint8_t) (domainLen << 3);
    *in1++ = (uint8_t) (domainLen << 3);
    *in2++ = (uint8_t) (domainLen << 3);
    *in3++ = (uint8_t) (domainLen << 3);
    memcpy(in0, domain0, domainLen);
    memcpy(in1, domain1, domainLen);
    memcpy(in2, domain2, domainLen);
    memcpy(in3, domain3, domainLen);
    in0 += domainLen;
    in1 += domainLen;
    in2 += domainLen;
    in3 += domainLen;
    
    inputLen = 2 + domainLen;
    
    assert( firstLen <= 8192 );
    if (firstLen < 32){
        *in0++ = 0x01;
        *in1++ = 0x01;
        *in2++ = 0x01;
        *in3++ = 0x01;
        *in0++ = (uint8_t) (firstLen << 3);
        *in1++ = (uint8_t) (firstLen << 3);
        *in2++ = (uint8_t) (firstLen << 3);
        *in3++ = (uint8_t) (firstLen << 3);
        inputLen += 2;
    } else {
        *in0++ = 0x02;
        *in1++ = 0x02;
        *in2++ = 0x02;
        *in3++ = 0x02;
        *in0++ = (uint8_t) ((firstLen << 3) >> 8);
        *in1++ = (uint8_t) ((firstLen << 3) >> 8);
        *in2++ = (uint8_t) ((firstLen << 3) >> 8);
        *in3++ = (uint8_t) ((firstLen << 3) >> 8);
        *in0++ = (uint8_t) (firstLen << 3);
        *in1++ = (uint8_t) (firstLen << 3);
        *in2++ = (uint8_t) (firstLen << 3);
        *in3++ = (uint8_t) (firstLen << 3);
        inputLen += 3;
    }
    memcpy(in0, first0, firstLen);
    memcpy(in1, first1, firstLen);
    memcpy(in2, first2, firstLen);
    memcpy(in3, first3, firstLen);
    in0 += firstLen;
    in1 += firstLen;
    in2 += firstLen;
    in3 += firstLen;
    
    inputLen += firstLen;
    
    if (numberOfElements == 3){
        
        assert( secondLen <= 2097152 );
        if (secondLen < 32){
            *in0++ = 0x01;
            *in1++ = 0x01;
            *in2++ = 0x01;
            *in3++ = 0x01;
            *in0++ = (uint8_t) (secondLen << 3);
            *in1++ = (uint8_t) (secondLen << 3);
            *in2++ = (uint8_t) (secondLen << 3);
            *in3++ = (uint8_t) (secondLen << 3);
            inputLen += 2;
        } else if (secondLen < 8192) {
            *in0++ = 0x02;
            *in1++ = 0x02;
            *in2++ = 0x02;
            *in3++ = 0x02;
            *in0++ = (uint8_t) ((secondLen << 3) >> 8);
            *in1++ = (uint8_t) ((secondLen << 3) >> 8);
            *in2++ = (uint8_t) ((secondLen << 3) >> 8);
            *in3++ = (uint8_t) ((secondLen << 3) >> 8);
            *in0++ = (uint8_t) (secondLen << 3);
            *in1++ = (uint8_t) (secondLen << 3);
            *in2++ = (uint8_t) (secondLen << 3);
            *in3++ = (uint8_t) (secondLen << 3);
            inputLen += 3;
        } else {
            *in0++ = 0x03;
            *in1++ = 0x03;
            *in2++ = 0x03;
            *in3++ = 0x03;
            *in0++ = (uint8_t) ((secondLen << 3) >> 16);
            *in1++ = (uint8_t) ((secondLen << 3) >> 16);
            *in2++ = (uint8_t) ((secondLen << 3) >> 16);
            *in3++ = (uint8_t) ((secondLen << 3) >> 16);
            *in0++ = (uint8_t) ((secondLen << 3) >> 8);
            *in1++ = (uint8_t) ((secondLen << 3) >> 8);
            *in2++ = (uint8_t) ((secondLen << 3) >> 8);
            *in3++ = (uint8_t) ((secondLen << 3) >> 8);
            *in0++ = (uint8_t) (secondLen << 3);
            *in1++ = (uint8_t) (secondLen << 3);
            *in2++ = (uint8_t) (secondLen << 3);
            *in3++ = (uint8_t) (secondLen << 3);
            inputLen += 4;
        }
        memcpy(in0, second0, secondLen);
        memcpy(in1, second1, secondLen);
        memcpy(in2, second2, secondLen);
        memcpy(in3, second3, secondLen);
        in0 += secondLen;
        in1 += secondLen;
        in2 += secondLen;
        in3 += secondLen;
        
        inputLen += secondLen;
        
    }
    
    
    if (outputLenBytes < 32){
        *in0++ = (uint8_t) (outputLenBytes << 3);
        *in1++ = (uint8_t) (outputLenBytes << 3);
        *in2++ = (uint8_t) (outputLenBytes << 3);
        *in3++ = (uint8_t) (outputLenBytes << 3);
        *in0++ = 0x01;
        *in1++ = 0x01;
        *in2++ = 0x01;
        *in3++ = 0x01;
        inputLen += 2;
        
    } else  if (outputLenBytes < 8192) {
        *in0++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in1++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in2++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in3++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        
        *in0++ = (uint8_t) (outputLenBytes << 3);
        *in1++ = (uint8_t) (outputLenBytes << 3);
        *in2++ = (uint8_t) (outputLenBytes << 3);
        *in3++ = (uint8_t) (outputLenBytes << 3);
        
        *in0++ = 0x02;
        *in1++ = 0x02;
        *in2++ = 0x02;
        *in3++ = 0x02;
        inputLen += 3;
        
    } else {

        *in0++ = (uint8_t) ((outputLenBytes << 3) >> 16);
        *in1++ = (uint8_t) ((outputLenBytes << 3) >> 16);
        *in2++ = (uint8_t) ((outputLenBytes << 3) >> 16);
        *in3++ = (uint8_t) ((outputLenBytes << 3) >> 16);
        
        *in0++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in1++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in2++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in3++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        
        *in0++ = (uint8_t) (outputLenBytes << 3);
        *in1++ = (uint8_t) (outputLenBytes << 3);
        *in2++ = (uint8_t) (outputLenBytes << 3);
        *in3++ = (uint8_t) (outputLenBytes << 3);
        
        *in0++ = 0x03;
        *in1++ = 0x03;
        *in2++ = 0x03;
        *in3++ = 0x03;
        inputLen += 4;
    }
    
    r5_xof_s_input_4x( &THContext->ccontext,
                    input0, input1, input2, input3, inputLen,
                    (const uint8_t *)("TupleHash"), 9,
                    NULL, NULL, NULL, NULL, 0
                    Params);
    
    free(input0);
    free(input1);
    free(input2);
    free(input3);
    
}

void r5_tuple_hash_xof_squeeze16_4x // tuple_hash_xof_squeeze
(
  uint16_t *output0,
  uint16_t *output1,
  uint16_t *output2,
  uint16_t *output3,
  uint32_t outputLen,
  TupleHash_Instance THContext
  Parameters )
{
    r5_xof_squeeze16_4x(&THContext->ccontext, output0, output1, output2, output3, outputLen Params);
}


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
 Parameters )
{
    ttupleHash_Instance thcontext = {0};
    r5_tuple_hash_input_4x(&thcontext, domain0, domain1, domain2, domain3, domainLen, first0, first1, first2, first3, firstLen,  second0, second1, second2, second3, secondLen, numberOfElements, 0 Params);
    r5_tuple_hash_xof_squeeze16_4x(output0, output1, output2, output3, outputLen, &thcontext Params);
}

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
 Parameters )
{
    ttupleHash_Instance thcontext = {0};
    r5_tuple_hash_input_4x(&thcontext, domain0, domain1, domain2, domain3, domainLen, first0, first1, first2, first3, firstLen,  second0, second1, second2, second3, secondLen, numberOfElements, 2*outputLen Params);
    r5_tuple_hash_xof_squeeze16_4x(output0, output1, output2, output3, outputLen, &thcontext Params);
}

#endif // AVX implementation


//	Local routines:

static inline void keccak_absorb
	( Context context,
     const uint8_t *input,
     size_t inputLength,
     uint8_t pad
     Parameters )
{
	while ( inputLength >= RATE ) {
		KeccakF1600_StateXORBytes(context->state, input Params);
		KeccakF1600_StatePermute(context->state);
		inputLength -= RATE;
		input += RATE;
	}
	memcpy(context->remaining, input, inputLength);
	context->remaining[inputLength] = pad;

	inputLength += 1;
	memset(&context->remaining[inputLength], 0x00, RATE - inputLength);
	context->remaining[RATE - 1] |= 0x80;
	KeccakF1600_StateXORBytes(context->state, context->remaining Params );
    
	context->index = &(context->remaining[RATE]);
}

// 	Exporting:

void r5_xof_input // init absorb finalize
	( Context context
	, const uint8_t *input, size_t inputLength Parameters )
{
	keccak_absorb(context, input, inputLength, 0x1F Params);
}

void r5_xof_squeeze
	( Context context
	, uint8_t *output, size_t outputLength Parameters )
{      
	uint8_t *buffer = context->index;
	size_t no = (size_t) ((&context->remaining[RATE]) - buffer);
	
	while( outputLength >= no ) {
		// memcpy( output, buffer, no );		
		while( buffer < &context->remaining[RATE] ) {
			*output++ = *buffer++; 
		}
		outputLength -= no;

		while( outputLength >= RATE ) {
			KeccakF1600_StatePermute(context->state);
            KeccakF1600_StateExtractBytes(context->state, output Params);
			outputLength -= RATE;
			output += RATE;
		}

		KeccakF1600_StatePermute(context->state);
        KeccakF1600_StateExtractBytes(context->state, context->remaining Params);
		no = RATE;
                buffer = context->remaining;
	}

	for ( size_t i = 0; i < outputLength; i++ ) {
	   *output++ = *buffer++;
	}
	context->index = buffer;
}


void r5_xof_squeeze16 
	( Context context
	, uint16_t *out, size_t outputLength Parameters )
{
	uint8_t *buffer = context->index;
	size_t no = (&context->remaining[RATE]) - buffer;
    
	uint8_t *output = ((uint8_t *) (out));
	outputLength *= 2;

	int d = -1;
	
	while( outputLength >= no ) {
		while( buffer < &context->remaining[RATE] ) {
			output[address] = *buffer++; 
			output++; 
		}
		outputLength -= no;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		while( outputLength >= RATE ) {
			KeccakF1600_StatePermute(context->state);
            KeccakF1600_StateExtractBytes(context->state, output Params);
			outputLength -= RATE;
			output += RATE;
		}
#endif
		KeccakF1600_StatePermute(context->state);
        KeccakF1600_StateExtractBytes(context->state, context->remaining Params);
		no = RATE;
                buffer = context->remaining;
	}
	for ( size_t i = 0; i < outputLength; i++ ) {
		output[address] = *buffer++; 
		output++; 
	}
	context->index = buffer;
}

void r5_xof // shake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters )
{
	ContextInstance context = {0}; 
	r5_xof_input(&context, input, inputLength Params); 
	r5_xof_squeeze(&context, output, outputLength Params);
}

void r5_xof16 // shake16
( uint16_t *output, size_t outputLength
 , const uint8_t *input, size_t inputLength Parameters)
{
    
    ContextInstance context = {0};
    r5_xof_input(&context, input, inputLength Params );
    r5_xof_squeeze16(&context, output, outputLength Params);
    
}

/******* cshake *******************/


void r5_xof_s_input // custom init absorb finalize of cshake
( CContext context,
 const uint8_t *input, size_t inputLength,
 const uint8_t *functionName, size_t functionnameLength,
 const uint8_t *customization, size_t customizationLength
 Parameters )
{
    if ((customizationLength == 0) && (functionnameLength == 0)){
        keccak_absorb(context, input, inputLength, 0x1F Params);
    } else {
        uint8_t *in = context->remaining;
        
        // bytepad(encode_string(N) || encode_string(S), rate)
        // left encoding of rate. Then string
        *in++ = 0x01; *in++ = RATE;
        
        // encode_string(N) = left_encode(N) || N. If N empty, 0x01 || 0x00
        *in++ = 0x01;
        assert( functionnameLength < 32 );
        *in++ = (uint8_t) (functionnameLength << 3);
        memcpy(in, functionName, functionnameLength);
        in += functionnameLength;
        
        // encode_string(S) = left_encode(S) || S. If S empty, 0x01 || 0x00
        *in++ = 0x01;
        assert( customizationLength < 32 );
        *in++ = (uint8_t) (customizationLength << 3);
        memcpy(in, customization, customizationLength);
        in += customizationLength;
        
        KeccakF1600_StateXORBytes(context->state, context->remaining Params );
        KeccakF1600_StatePermute(context->state);
        
        keccak_absorb(context, input, inputLength, 0x04 Params );
    }
}



void r5_xof_s_squeeze
    ( CContext context
    , uint8_t *output, size_t outputLength Parameters )
{ r5_xof_squeeze(context, output, outputLength Params ); }

void r5_xof_s_squeeze16
    ( CContext context
    , uint16_t *output, size_t outputLength Parameters )
{
    r5_xof_squeeze16(context, output, outputLength Params );
}

void r5_xof_sn // cshake with N = NULL
    ( uint8_t *output, size_t outputLength
    , const uint8_t *input, size_t inputLength
    , const uint8_t *customization, size_t customizationLength Parameters )
{
    ContextInstance context = {0};
    r5_xof_s_input(&context, input, inputLength, NULL, 0, customization, customizationLength Params);
    r5_xof_squeeze(&context, output, outputLength Params );
}

void r5_xof_s16 // cshake16 with N = NULL
    ( uint16_t *output, size_t outputLength
    , const uint8_t *input, size_t inputLength
    , const uint8_t *customization, size_t customizationLength Parameters )
{
    ContextInstance context = {0};
    r5_xof_s_input(&context, input, inputLength, NULL, 0, customization, customizationLength Params );
    r5_xof_squeeze16(&context, output, outputLength Params );
}

/********** tuplehash ****************/

void r5_tuple_hash_input // tuple_hash_input for tuple with up to three strings 
( THContextInstance tinstance,
 const uint8_t *domain, uint8_t domainLen,
 const uint8_t *first, uint16_t firstLen,
 const uint8_t *second,  uint32_t secondLen,
 uint8_t numberOfElements,
 uint32_t outputLenBytes
 Parameters )
{
    // ToDo: this memory overhead goes away by absorbing the input into the state
    uint8_t *inputbuff;
    inputbuff = checked_malloc(14 + domainLen + firstLen + secondLen);
    
    uint8_t *in = inputbuff;
    uint32_t inputLen = 0;
    
    *in++ = 0x01;
    assert( domainLen < 32 );
    *in++ = (uint8_t) (domainLen << 3);
    memcpy(in, domain, domainLen);
    in += domainLen;
    
    inputLen = 2 + domainLen;
    
    assert( firstLen <= 8192 );
    if (firstLen < 32){
        *in++ = 0x01;
        *in++ = (uint8_t) (firstLen << 3);
        inputLen += 2;
    } else {
        *in++ = 0x02;
        *in++ = (uint8_t) ((firstLen << 3) >> 8);
        *in++ = (uint8_t) (firstLen << 3);
        inputLen += 3;
    }
    memcpy(in, first, firstLen);
    in += firstLen;
    inputLen += firstLen;
    
    if (numberOfElements == 3){
    
    assert( secondLen <= 2097152 );
    if (secondLen < 32){
        *in++ = 0x01;
        *in++ = (uint8_t) (secondLen << 3);
        inputLen += 2;
    } else if (secondLen < 8192) {
        *in++ = 0x02;
        *in++ = (uint8_t) ((secondLen << 3) >> 8);
        *in++ = (uint8_t) (secondLen << 3);
        inputLen += 3;
    } else {
        *in++ = 0x03;
        *in++ = (uint8_t) ((secondLen << 3) >> 16);
        *in++ = (uint8_t) ((secondLen << 3) >> 8);
        *in++ = (uint8_t) (secondLen << 3);
        inputLen += 4;
    }
    memcpy(in, second, secondLen);
    in += secondLen;
    inputLen += secondLen;

    }
    
    // right encoding of output bytes. If xof, it is always zero.
    //*in++ = 0x00;
    //*in++ = 0x01;
    //inputLen += 2;

    if (outputLenBytes < 32){
        *in++ = (uint8_t) (outputLenBytes << 3);
        
        *in++ = 0x01;
        inputLen += 2;
    } else if (outputLenBytes < 8192) {
        *in++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in++ = (uint8_t) (outputLenBytes << 3);
        
        *in++ = 0x02;
        inputLen += 3;
    } else {
        *in++ = (uint8_t) ((outputLenBytes << 3) >> 16);
        *in++ = (uint8_t) ((outputLenBytes << 3) >> 8);
        *in++ = (uint8_t) (outputLenBytes << 3);
        
        inputLen += 4;
        *in++ = 0x03;
    }
    
    r5_xof_s_input( &tinstance->ccontext,
                    inputbuff, inputLen,
                    (const uint8_t *)("TupleHash"), 9,
                    NULL, 0
                    Params);
    free(inputbuff);
    
}

void r5_tuple_hash_xof_squeeze // tuple_hash_xof_squeeze
( uint8_t *output, uint32_t outputLen,
 TupleHash_Instance THContext
 Parameters )
{
    r5_xof_squeeze(&THContext->ccontext, output, outputLen Params);
}

void r5_tuple_hash_xof_squeeze16 // tuple_hash_xof_squeeze
( uint16_t *output, uint32_t outputLen,
 THContextInstance tinstance
 Parameters )
{
    r5_xof_squeeze16(&tinstance->ccontext, output, outputLen Params);
}


void r5_tuple_hash_xof
    (uint8_t *output, uint32_t outputLen,
     const uint8_t *domain, uint8_t domainLen,
     const uint8_t *first, uint16_t firstLen,
     const uint8_t *second, uint32_t secondLen,
     uint8_t numberOfElements
     Parameters
     )
{
    ttupleHash_Instance thcontext = {0};
    r5_tuple_hash_input(&thcontext, domain, domainLen, first, firstLen,  second, secondLen, numberOfElements, 0 Params);
    r5_tuple_hash_xof_squeeze(output, outputLen, &thcontext Params);
}

void r5_tuple_hash_xof16
(uint16_t *output, uint32_t outputLen,
 const uint8_t *domain, uint8_t domainLen,
 const uint8_t *first, uint16_t firstLen,
 const uint8_t *second, uint32_t secondLen,
 uint8_t numberOfElements
 Parameters
 )
{
    ttupleHash_Instance thcontext = {0};
    r5_tuple_hash_input(&thcontext, domain, domainLen, first, firstLen,  second, secondLen, numberOfElements, 0 Params);
    r5_tuple_hash_xof_squeeze16(output, outputLen, &thcontext Params);
}


void r5_tuple_hash
(uint8_t *output, uint32_t outputLen,
 const uint8_t *domain, uint8_t domainLen,
 const uint8_t *first, uint16_t firstLen,
 const uint8_t *second, uint32_t secondLen,
 uint8_t numberOfElements
 Parameters
 )
{
    ttupleHash_Instance thcontext = {0};
    r5_tuple_hash_input(&thcontext, domain, domainLen, first, firstLen,  second, secondLen, numberOfElements, outputLen Params);
    r5_tuple_hash_xof_squeeze(output, outputLen, &thcontext Params);
}

void r5_tuple_hash16
(uint16_t *output, uint32_t outputLen,
 const uint8_t *domain, uint8_t domainLen,
 const uint8_t *first, uint16_t firstLen,
 const uint8_t *second, uint32_t secondLen,
 uint8_t numberOfElements
 Parameters
 )
{
    ttupleHash_Instance thcontext = {0};
    r5_tuple_hash_input(&thcontext, domain, domainLen, first, firstLen,  second, secondLen, numberOfElements, 2*outputLen Params);
    r5_tuple_hash_xof_squeeze16(output, outputLen, &thcontext Params);
}

#else

/************* NOT STANDALONE *****************************************/

#define failsafe(X) if ((X) != 0) abort()

void r5_xof_input // init absorb finalize
	( Context context
	, const uint8_t *input, size_t inputLength Parameters )
{
	if( PARAMS_KAPPA_BYTES > 16 ) {
		failsafe( Keccak_HashInitialize_SHAKE256(context) ) ;
	}
    
	else {
		failsafe( Keccak_HashInitialize_SHAKE128(context) ) ;
	}

	failsafe( Keccak_HashUpdate(context, input, inputLength * 8) );
	failsafe( Keccak_HashFinal(context, NULL) );
}

void r5_xof_squeeze
	( Context context
	, uint8_t *output, size_t outputLength Parameters )
{ useParams failsafe( Keccak_HashSqueeze(context, output, outputLength * 8) ); }

void r5_xof_squeeze16 
	( Context context
	, uint16_t *out, size_t outputLength Parameters )
{
	uint8_t * output = (uint8_t *) out;
	outputLength *= 2;

	r5_xof_squeeze(context, output, outputLength Params); 
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	for(int i = 0; i < outputLength; i+=2 ) {
		uint8_t h = output[i]; output[i] = output[i+1]; output[i+1] = h; 
	}
#endif
}

void r5_xof // shake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters )
{
	ContextInstance context = {0}; 
	r5_xof_input(&context, input, inputLength Params ); 
	r5_xof_squeeze(&context, output, outputLength Params );
}

void r5_xof16 // shake16
	( uint16_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength Parameters )
{
	ContextInstance context = {0};
	r5_xof_input(&context, input, inputLength Params );
	r5_xof_squeeze16(&context, output, outputLength Params );
}

/************* cshake ***********************************/

void r5_xof_s_input // custom init absorb finalize
    ( CContext context,
     const uint8_t *input, size_t inputLength,
     const uint8_t *functionName, size_t functionnameLength,
     const uint8_t *customization, size_t customizationLength
     Parameters )
{
        if ( PARAMS_KAPPA_BYTES > 16) {
        failsafe( cSHAKE256_Initialize(context, 0, NULL, 0, customization, customizationLength * 8) );
        failsafe( cSHAKE256_Update(context, input, inputLength * 8) );
        failsafe( cSHAKE256_Final(context, NULL) );
    }
    else {
        failsafe( cSHAKE128_Initialize(context, 0, NULL, 0, customization, customizationLength * 8) );
        failsafe( cSHAKE128_Update(context, input, inputLength * 8) );
        failsafe( cSHAKE128_Final(context, NULL) );
    }
}

void r5_xof_s_squeeze
	( CContext context
	, uint8_t *output, size_t outputLength Parameters )
{
	if  ( PARAMS_KAPPA_BYTES > 16) {
		failsafe( cSHAKE256_Squeeze(context, output, outputLength * 8) );
	}
	else {
		failsafe( cSHAKE128_Squeeze(context, output, outputLength * 8) );
	}
}


void r5_xof_s_squeeze16
	( CContext context
	, uint16_t *out, size_t outputLength Parameters )
{
	uint8_t * output = (uint8_t *) out;
	outputLength *= 2;

	r5_xof_s_squeeze(context, output, outputLength Params );
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__	
	for(int i = 0; i < outputLength; i+=2 ) {
		uint8_t h = output[i]; output[i] = output[i+1]; output[i+1] = h; 
	}
#endif
}


void r5_xof_s // cshake
	( uint8_t *output, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters )
{
	if (PARAMS_KAPPA_BYTES > 16) {
		failsafe( cSHAKE256(input, inputLength * 8 , output, outputLength * 8
			, NULL, 0, customization, customizationLength * 8) );
	}
	else {
		failsafe( cSHAKE128(input, inputLength * 8 , output, outputLength * 8
			, NULL, 0, customization, customizationLength * 8) );
	}
} 

void r5_xof_s16 // cshake
	( uint16_t *out, size_t outputLength
	, const uint8_t *input, size_t inputLength
	, const uint8_t *customization, size_t customizationLength Parameters )
{
	uint8_t * output = (uint8_t *) out;
	outputLength *= 2;

	r5_xof_s( output, outputLength, input, inputLength
		, customization, customizationLength Params );
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__	
	for(int i = 0; i < outputLength; i+=2 ) {
		uint8_t h = output[i]; output[i] = output[i+1]; output[i+1] = h; 
	}
#endif
}

/**************** tuple_hash ********************************/

void r5_tuple_hash 
( uint8_t *output, uint32_t outputLen,
  const uint8_t *domain, uint8_t domainLen,
  const uint8_t *first, uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements
  Parameters )
{
    const TupleElement tupleinput[3] = {{domain, 8*domainLen},{first, 8*firstLen},{second, 8*secondLen}};

    if (PARAMS_KAPPA_BYTES > 16) {

        failsafe( TupleHash256( tupleinput, numberOfElements,
                               output, 8*outputLen, NULL, 0) );

    }
    else {

        failsafe( TupleHash128( tupleinput, numberOfElements,
                               output, 8*outputLen, NULL, 0) );

    }
}

void r5_tuple_hash16
( uint16_t *out, uint32_t outputLen,
  const uint8_t *domain, uint8_t domainLen,
  const uint8_t *first, uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements
  Parameters)
{
    uint8_t * output = (uint8_t *) out;
    outputLen *= 2;
    
    r5_tuple_hash( output, outputLen, domain, domainLen, first, firstLen, second, secondLen, numberOfElements Params );
    
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    for(int i = 0; i < outputLength; i+=2 ) {
        uint8_t h = output[i]; output[i] = output[i+1]; output[i+1] = h;
    }
#endif
    
}


void r5_tuple_hash_xof
( uint8_t *output, uint32_t outputLen,
  const uint8_t *domain, uint8_t domainLen,
  const uint8_t *first, uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements
  Parameters
 )
{

    const TupleElement tupleinput[3] = {{domain, 8*domainLen},{first, 8*firstLen},{second, 8*secondLen}};

    TupleHash_Instance tinstance = {0};

    if (PARAMS_KAPPA_BYTES > 16) {
        
        failsafe( TupleHash256_Initialize(&tinstance, 0, NULL, 0) );
        failsafe( TupleHash256_Update(&tinstance, tupleinput, numberOfElements) );
        failsafe( TupleHash256_Final(&tinstance, NULL) );
        
        failsafe( TupleHash256_Squeeze(&tinstance, output, 8*outputLen) );
    }
    else {
        
        failsafe( TupleHash128_Initialize(&tinstance, 0, NULL, 0) );
        failsafe( TupleHash128_Update(&tinstance, tupleinput, numberOfElements) );
        failsafe( TupleHash128_Final(&tinstance, NULL) );
        failsafe( TupleHash128_Squeeze(&tinstance, output, 8*outputLen) );
        
    }
}

void r5_tuple_hash_xof16
( uint16_t *out, uint32_t outputLen,
  const uint8_t *domain, uint8_t domainLen,
  const uint8_t *first, uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements
  Parameters)
{
    uint8_t * output = (uint8_t *) out;
    outputLen *= 2;
    
    r5_tuple_hash_xof( output, outputLen, domain, domainLen,
                      first, firstLen, second, secondLen,
                      numberOfElements Params );
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    for(int i = 0; i < outputLength; i+=2 ) {
        uint8_t h = output[i]; output[i] = output[i+1]; output[i+1] = h;
    }
#endif
}

void r5_tuple_hash_input // tuple_hash_xof_input
( THContextInstance tinstance,
  const uint8_t *domain, const uint8_t domainLen,
  const uint8_t *first, const uint16_t firstLen,
  const uint8_t *second, uint32_t secondLen,
  uint8_t numberOfElements,
  uint32_t outputLen
 Parameters )
{
    const TupleElement tupleinput[3] = {{domain, 8*domainLen},{first, 8*firstLen},{second, 8*secondLen}};
    
    if (PARAMS_KAPPA_BYTES > 16) {
        failsafe( TupleHash256_Initialize(tinstance, 0 , NULL, 0) );
        failsafe( TupleHash256_Update(tinstance, tupleinput, numberOfElements) );
        failsafe( TupleHash256_Final(tinstance, NULL) );
    }
    else {
        failsafe( TupleHash128_Initialize(tinstance, 0, NULL, 0) );
        failsafe( TupleHash128_Update(tinstance, tupleinput, numberOfElements) );
        failsafe( TupleHash128_Final(tinstance, NULL) );
    }
}

void r5_tuple_hash_xof_squeeze // tuple_hash_xof_squeeze
( uint8_t *output, size_t outputLen,
  TupleHash_Instance *tinstance
  Parameters )
{
    
    if (PARAMS_KAPPA_BYTES > 16) {
        
        failsafe( TupleHash256_Squeeze(tinstance, output, 8*outputLen) );
    }
    else {

        failsafe( TupleHash128_Squeeze(tinstance, output, 8*outputLen) );
        
    }
}

void r5_tuple_hash_xof_squeeze16 // tuple_hash_xof_squeeze
( uint16_t *out, uint32_t outputLen,
  THContextInstance tinstance
  Parameters )
{
    uint8_t * output = (uint8_t *) out;
    outputLen *= 2;

    r5_tuple_hash_xof_squeeze( output, outputLen, tinstance Params );
   
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    for(int i = 0; i < outputLength; i+=2 ) {
        uint8_t h = output[i]; output[i] = output[i+1]; output[i+1] = h;
    }
#endif
    
}

#define freeContext(context)

#endif



