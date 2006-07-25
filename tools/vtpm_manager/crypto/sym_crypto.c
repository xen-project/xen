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
// sym_crypto.c
// 
//     Symmetric crypto portion of crypto 
// 
// ==================================================================

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "tcg.h"
#include "sym_crypto.h"

typedef enum crypt_op_type_t {
  CRYPT_ENCRYPT,
  CRYPT_DECRYPT
} crypt_op_type_t;

TPM_RESULT ossl_symcrypto_op (symkey_t* key,
                              const buffer_t* in,
                              const buffer_t* iv,
                              buffer_t * out,
                              crypt_op_type_t optype);


// this is initialized in Crypto_Init()
const EVP_CIPHER * SYM_CIPHER = NULL;

const BYTE ZERO_IV[EVP_MAX_IV_LENGTH] = {0};


TPM_RESULT Crypto_symcrypto_initkey (symkey_t * key, const buffer_t* keybits) {
  TPM_RESULT status = TPM_SUCCESS;
  
  EVP_CIPHER_CTX_init (&key->context);
  
  key->cipher = SYM_CIPHER;
  
  TPMTRYRETURN( buffer_init_copy (&key->key, keybits));
    
  goto egress;
  
 abort_egress:
  EVP_CIPHER_CTX_cleanup (&key->context);
  
 egress:
  
  return status;
}



TPM_RESULT Crypto_symcrypto_genkey (symkey_t * key) {
  int res;
  TPM_RESULT status = TPM_SUCCESS;
  
  // hmm, EVP_CIPHER_CTX_init does not return a value
  EVP_CIPHER_CTX_init (&key->context);
  
  key->cipher = SYM_CIPHER;
  
  TPMTRYRETURN( buffer_init (&key->key, EVP_CIPHER_key_length(key->cipher), NULL)) ;
  
  // and generate the key material
  res = RAND_pseudo_bytes (key->key.bytes, key->key.size);
  if (res < 0) 
    ERRORDIE (TPM_SHORTRANDOM);
  
  
  goto egress;
  
 abort_egress:
  EVP_CIPHER_CTX_cleanup (&key->context);
  buffer_free (&key->key);
  
 egress:
  return status;  
}


TPM_RESULT Crypto_symcrypto_encrypt (symkey_t* key,
                              const buffer_t* clear,
                              buffer_t* o_cipher) {
  TPM_RESULT status = TPM_SUCCESS;
  
  buffer_t iv, cipher_alias;
  
  buffer_init_const (&iv, EVP_MAX_IV_LENGTH, ZERO_IV);
  
  buffer_init (o_cipher,
	       clear->size +
	       EVP_CIPHER_iv_length(key->cipher) +
	       EVP_CIPHER_block_size (key->cipher),
				 0);
  
  // copy the IV into the front
  buffer_copy (o_cipher, &iv);
  
  // make an alias into which we'll put the ciphertext
  buffer_init_alias (&cipher_alias, o_cipher, EVP_CIPHER_iv_length(key->cipher), 0);
  
  TPMTRYRETURN( ossl_symcrypto_op (key, clear, &iv, &cipher_alias, CRYPT_ENCRYPT) );

  // set the output size correctly
  o_cipher->size += cipher_alias.size;
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  return status;
  
}



TPM_RESULT Crypto_symcrypto_decrypt (symkey_t* key,
                              const buffer_t* cipher,
                              buffer_t* o_clear) {
  TPM_RESULT status = TPM_SUCCESS;
  
  buffer_t iv, cipher_alias;
  
  // alias for the IV
  buffer_init_alias (&iv, cipher, 0, EVP_CIPHER_iv_length(key->cipher));
  
  // make an alias to where the ciphertext is, after the IV
  buffer_init_alias (&cipher_alias, cipher, EVP_CIPHER_iv_length(key->cipher), 0);
  
  // prepare the output buffer
  TPMTRYRETURN( buffer_init (o_clear,
			cipher->size
			- EVP_CIPHER_iv_length(key->cipher)
			+ EVP_CIPHER_block_size(key->cipher), 
			0) );
  
  // and decrypt
  TPMTRYRETURN ( ossl_symcrypto_op (key, &cipher_alias, &iv, o_clear, CRYPT_DECRYPT) );
  
  goto egress;
  
 abort_egress:
  buffer_free (o_clear);
  
 egress:
  
  return status;
}



TPM_RESULT Crypto_symcrypto_freekey (symkey_t * key) {
  buffer_memset (&key->key, 0);
  buffer_free (&key->key);
  
  EVP_CIPHER_CTX_cleanup (&key->context);
  
  return TPM_SUCCESS;
}


TPM_RESULT ossl_symcrypto_op (symkey_t* key,
                              const buffer_t* in,
                              const buffer_t* iv,
                              buffer_t * out,
                              crypt_op_type_t optype) {
  TPM_RESULT status = TPM_SUCCESS;
  
  int inlen, outlen;
  tpm_size_t running;
  
  if ( ! EVP_CipherInit_ex (&key->context,
			    key->cipher, NULL, key->key.bytes, iv->bytes,
			    optype == CRYPT_ENCRYPT ? 1 : 0) ) 
    ERRORDIE (TPM_FAIL);
  
  
  
  inlen = in->size;
  
  outlen  = 0;
  running = 0;
  
  
  if ( ! EVP_CipherUpdate (&key->context, out->bytes, &outlen, in->bytes, inlen) )
    ERRORDIE (TPM_FAIL);

  running += outlen;
  
  if ( ! EVP_CipherFinal_ex (&key->context, out->bytes + running, &outlen) )
    ERRORDIE (TPM_FAIL);
  
  running += outlen;
  
  out->size = running;
  
  goto egress;
  
 abort_egress:
 egress:
  
  return status;
}
