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
// crypto.c
// 
//  This file will handle all the TPM Crypto functionality
// 
// ==================================================================

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"
#include "log.h"

/**
 * Initialize cryptography library
 * @rand: random seed
 * @size: size of @rand
 */
void Crypto_Init(const BYTE* rand, int size) {
	ERR_load_crypto_strings();
  CRYPTO_malloc_init();
  OpenSSL_add_all_algorithms();
  SYM_CIPHER = EVP_aes_128_cbc();
  RAND_poll();
  if (rand == NULL)
    return;

  RAND_add(rand, size, size);
}

/**
 * Shutdown cryptography library
 */
void Crypto_Exit() {
  ERR_free_strings();
  ERR_remove_state(0);
  EVP_cleanup();
}


/**
 * Get random data
 * @data: (OUT) Random data
 * @size: Size of @data
 */
void Crypto_GetRandom(void* data, int size) {
  int result;
  
  result = RAND_pseudo_bytes((BYTE*) data, size);
  
  if (result <= 0) 
    vtpmlogerror (VTPM_LOG_CRYPTO, "RAND_pseudo_bytes failed: %s\n",
	     ERR_error_string (ERR_get_error(), NULL));
}
