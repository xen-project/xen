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
// hash.c
// 
//  This file will handle all the TPM Hash functionality
//
// ==================================================================

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "tcg.h"         // for TPM_SUCCESS
#include "crypto.h"

static SHA_CTX g_shaContext;

void Crypto_HMAC(   const BYTE* text, 
                    int text_len, 
                    const BYTE* key, 
                    int key_len, 
                    BYTE* digest) {
  if (text == NULL || key == NULL || text_len == 0 || key_len == 0) 
    return;
  
  HMAC(EVP_sha1(), key, key_len, text, text_len, digest, NULL);
}

TPM_RESULT Crypto_HMAC_buf (const buffer_t * text,
			    const buffer_t * key,
			    BYTE * o_digest) { /* presumably of 20 bytes */
  
  Crypto_HMAC (text->bytes, text->size, 
	       key->bytes, key->size,
	       o_digest);
  
  return TPM_SUCCESS;
}


/*
 * SHA1
 * (OUT) Create a SHA1 hash of text. Calls all three SHA1 steps internally
 */
void Crypto_SHA1Full( const BYTE* text, 
      uint32_t size, 
      BYTE* hash) {

  if (text == NULL || size == 0) 
    return;
  
  // Run SHA1Start + SHAUpdate (if necessary) + SHAComplete
  uint32_t maxBytes; // Not used for anything
  Crypto_SHA1Start(&maxBytes);
  
  while (size > 64){
    Crypto_SHA1Update(64, text); 
    size -= 64;
    text += 64;
  }
  
  Crypto_SHA1Complete(size, text, hash);
}

// same thing using buffer_t
TPM_RESULT Crypto_SHA1Full_buf (const buffer_t * buf,
                                 BYTE * o_digest) {

  if (buf->bytes == NULL || buf->size == 0) 
    return TPM_BAD_PARAMETER;
  
  Crypto_SHA1Full (buf->bytes, buf->size, o_digest);
  
  return TPM_SUCCESS;
}


/*
 * Initialize SHA1
 * (OUT) Maximum number of bytes that can be sent to SHA1Update. 
 *   Must be a multiple of 64 bytes.
 */
void Crypto_SHA1Start(uint32_t* maxNumBytes) {
  int max = SHA_CBLOCK;
  // Initialize the crypto library
  SHA1_Init(&g_shaContext);
  *maxNumBytes = max;
}

/*
 * Process SHA1
 * @numBytes: (IN) The number of bytes in hashData. 
 *       Must be a multiple of 64 bytes.
 * @hashData: (IN) Bytes to be hashed.
 */
void Crypto_SHA1Update(int numBytes, const BYTE* hashData) {

  if (hashData == NULL || numBytes == 0 || numBytes%64 != 0) 
    return;
  
  SHA1_Update(&g_shaContext, hashData, numBytes); 
}

/*
 * Complete the SHA1 process
 * @hashDataSize: (IN) Number of bytes in hashData.
 *       Must be a multiple of 64 bytes.
 * @hashData: (IN) Final bytes to be hashed.
 * @hashValue: (OUT) The output of the SHA-1 hash.
 */
void Crypto_SHA1Complete(int hashDataSize, 
			 const BYTE* hashData, 
			 BYTE* hashValue) {
  SHA1_Update(&g_shaContext, hashData, hashDataSize);
  SHA1_Final(hashValue, &g_shaContext);
}
