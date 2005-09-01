// ===================================================================
// 
// Copyright (c) 2005, Intel Corp.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions 
// are met:
//
//   * Redistributions of source code must retain the above copyright 
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above 
//     copyright notice, this list of conditions and the following 
//     disclaimer in the documentation and/or other materials provided 
//     with the distribution.
//   * Neither the name of Intel Corporation nor the names of its 
//     contributors may be used to endorse or promote products derived
//     from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.
// ===================================================================
// 
// crypto.h
// 
//  This file defines the TPM Crypto API
//
// ==================================================================

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "tcg.h"
#include "sym_crypto.h"

#define CRYPTO_MAX_SIG_SIZE (2048 / 8)
#define CRYPTO_MAX_RSA_KEY_SIZE (4096 / 8) //in bytes

#define OAEP_P "TCPA"
#define OAEP_P_SIZE 4

// Algorithms supported by crypto. Stored in CRYPTO_INFO.algorithmID
#define CRYPTO_ALGORITH_RSA 0x01

// Supported Encryption Schemes CRYPTO_INFO.encScheme
#define CRYPTO_ES_NONE 0x0001
#define CRYPTO_ES_RSAESPKCSv15 0x0002
#define CRYPTO_ES_RSAESOAEP_SHA1_MGF1 0x0003

// Supported Signature schemes CRYPTO_INFO.sigScheme
#define CRYPTO_SS_NONE 0x0001
#define CRYPTO_SS_RSASSAPKCS1v15_SHA1 0x0002
#define CRYPTO_SS_RSASSAPKCS1v15_DER 0x0003

typedef struct CRYPTO_INFO {
  void *keyInfo;
  UINT32 algorithmID;
  UINT32 encScheme;
  UINT32 sigScheme;
} CRYPTO_INFO;


void Crypto_Init(const BYTE* rand, int size);

void Crypto_Exit();

void Crypto_GetRandom(void* data, int size);

void Crypto_HMAC(   const BYTE* text, 
                    int text_len, 
                    const BYTE* key, 
                    int key_len,
                    BYTE* digest);

TPM_RESULT Crypto_HMAC_buf (const buffer_t * text,
                            const buffer_t * key,
                            BYTE * o_digest); /* presumably of 20 bytes */
    
void Crypto_SHA1Full(   const BYTE* text, 
                        UINT32 size,
                        BYTE* hash); //Complete 3part SHA1

// o_hash needs to be large enough to hold the digest, ie 20 bytes
TPM_RESULT Crypto_SHA1Full_buf (const buffer_t * buf,
                                BYTE * o_hash);
    
void Crypto_SHA1Start(UINT32* maxNumBytes);
void Crypto_SHA1Update(int numBytes, const BYTE* hashData);
void Crypto_SHA1Complete(   int hashDataSize, 
                            const BYTE* hashData, 
                            BYTE* hashValue);

void Crypto_RSACreateKey(   /*in*/ UINT32 keySize,
                            /*in*/ UINT32 pubExpSize, 
                            /*in*/ BYTE *pubExp,
                            /*out*/ UINT32 *privExpSize, 
                            /*out*/ BYTE *privExp,
                            /*out*/ UINT32 *modulusSize,
                            /*out*/ BYTE *modulus,
                            /*out*/ CRYPTO_INFO *keys);
                            
void Crypto_RSABuildCryptoInfo( /*[IN]*/ UINT32 pubExpSize, 
                                /*[IN]*/ BYTE *pubExp,
                                /*[IN]*/ UINT32 privExpSize, 
                                /*[IN]*/ BYTE *privExp,
                                /*[IN]*/ UINT32 modulusSize, 
                                /*[IN]*/ BYTE *modulus, 
                                /*[OUT]*/ CRYPTO_INFO* cryptoInfo);
                                
void Crypto_RSABuildCryptoInfoPublic(   /*[IN]*/ UINT32 pubExpSize, 
                                        /*[IN]*/ BYTE *pubExp,
                                        /*[IN]*/ UINT32 modulusSize, 
                                        /*[IN]*/ BYTE *modulus, 
                                        CRYPTO_INFO* cryptoInfo);

//
// symmetric pack and unpack operations
//
TPM_RESULT Crypto_RSAPackCryptoInfo (const CRYPTO_INFO* cryptoInfo,
                                     BYTE ** io_buf, UINT32 * io_buflen);

TPM_RESULT Crypto_RSAUnpackCryptoInfo (CRYPTO_INFO * ci,
                                       BYTE * in, UINT32 len,
                                       UINT32 * o_lenread);

                             
// return 0 on success, -1 on error
int Crypto_RSAEnc(  CRYPTO_INFO *keys,
                    UINT32 inDataSize,
                    BYTE *inData,
                    /*out*/ UINT32 *outDataSize,
                    /*out*/ BYTE *outData);

// return 0 on success, -1 on error
int Crypto_RSADec(  CRYPTO_INFO *keys,
                    UINT32 inDataSize,
                    BYTE *inData,
                    /*out*/ UINT32 *outDataSize,
                    /*out*/ BYTE *outData);

// return 0 on success, -1 on error
int Crypto_RSASign( CRYPTO_INFO *keys,
                    UINT32 inDataSize,
                    BYTE *inData,
                    /*out*/ UINT32 *sigSize,
                    /*out*/ BYTE *sig);

bool Crypto_RSAVerify(  CRYPTO_INFO *keys,
                        UINT32 inDataSize,
                        BYTE *inData,
                        UINT32 sigSize,
                        BYTE *sig);

//private:
int RSA_verify_DER(int dtype, unsigned char *m, unsigned int m_len,
                   unsigned char *sigbuf, unsigned int siglen, CRYPTO_INFO *key);

int RSA_sign_DER(int type, unsigned char *m, unsigned int m_len,
              unsigned char *sigret, unsigned int *siglen, CRYPTO_INFO *key);

#endif // __CRYPTO_H__
