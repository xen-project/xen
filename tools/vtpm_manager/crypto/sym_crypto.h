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
// sym_crypto.h
// 
//     Symmetric Crypto 
// 
// ==================================================================

#ifndef _SYM_CRYPTO_H
#define _SYM_CRYPTO_H

#include <openssl/evp.h>
#include "buffer.h"

typedef struct symkey_t {
  buffer_t key;
  
  EVP_CIPHER_CTX context;
  const EVP_CIPHER * cipher;
} symkey_t;

extern const EVP_CIPHER * SYM_CIPHER;

TPM_RESULT Crypto_symcrypto_genkey (symkey_t * key);

TPM_RESULT Crypto_symcrypto_initkey (symkey_t * key, const buffer_t* keybits);


// these functions will allocate their output buffers
TPM_RESULT Crypto_symcrypto_encrypt (symkey_t* key,
                              const buffer_t* clear,
                              buffer_t* o_cipher);

TPM_RESULT Crypto_symcrypto_decrypt (symkey_t* key,
                              const buffer_t* cipher,
                              buffer_t* o_clear);

// only free the internal parts, not the 'key' ptr
TPM_RESULT Crypto_symcrypto_freekey (symkey_t * key);

#endif /* _SYM_CRYPTO_H */
