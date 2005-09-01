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
// rsa.c
// 
//  This file will handle all the TPM RSA crypto functionality
// 
// ==================================================================

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <openssl/err.h>
#include <stdio.h>

#include "tcg.h"
#include "buffer.h"
#include "crypto.h"
#include "log.h"

void Crypto_RSACreateKey(   /*in*/ UINT32 keySize,
                            /*in*/ UINT32 pubExpSize, 
                            /*in*/ BYTE *pubExp,
                            /*out*/ UINT32 *privExpSize, 
                            /*out*/ BYTE *privExp,
                            /*out*/ UINT32 *modulusSize,        
                            /*out*/ BYTE *modulus,
                            /*out*/ CRYPTO_INFO *keys) {
  unsigned long e_value;
  
  if (pubExpSize == 0) // Default e = 2^16+1
    e_value = (0x01 << 16) + 1;
  else {
    // This is not supported, but the following line MIGHT work
    // under then assumption that the format is BigNum compatable
    // Though it's not in the spec, so who knows what it is.
    // Forcing the default.
    //BN_bin2bn(pubExp, pubExpSize, NULL);
    e_value = (0x01 << 16) + 1;
  }

  RSA *rsa = RSA_generate_key(keySize, e_value, NULL, NULL);
  
  if (keys) {
    keys->keyInfo = rsa;
    keys->algorithmID = CRYPTO_ALGORITH_RSA;
  }
  
  if (modulus)   *modulusSize   = BN_bn2bin(rsa->n, modulus);
  if (privExp)   *privExpSize   = BN_bn2bin(rsa->d, privExp);
}

// Create a CRYPTO_INFO struct from the BYTE * key parts. 
// If pubExp info is NULL, use TCG default.
// If there is a remainder while calculating the privExp, return FALSE.

void Crypto_RSABuildCryptoInfo( /*[IN]*/ UINT32 pubExpSize, 
                                /*[IN]*/ BYTE *pubExp,
                                /*[IN]*/ UINT32 privExpSize, 
                                /*[IN]*/ BYTE *privExp,
                                /*[IN]*/ UINT32 modulusSize, 
                                /*[IN]*/ BYTE *modulus, 
                                CRYPTO_INFO* cryptoInfo) {
  cryptoInfo->keyInfo = RSA_new();
  RSA *rsa = (RSA *) cryptoInfo->keyInfo;
  
  rsa->e = BN_new();
  
  if (pubExpSize == 0) { // Default e = 2^16+1
    BN_set_bit(rsa->e, 16);
    BN_set_bit(rsa->e, 0);
  } else {
    // This is not supported, but the following line MIGHT work
    // under then assumption that the format is BigNum compatable
    // Though it's not in the spec, so who knows what it is.
    // Forcing the default.
    //BN_bin2bn(pubExp, pubExpSize, NULL);
    BN_set_bit(rsa->e, 16);
    BN_set_bit(rsa->e, 0);
  }
  
  rsa->n = BN_bin2bn(modulus, modulusSize, NULL);
  rsa->d = BN_bin2bn(privExp, privExpSize, NULL);
}

// Create a CRYPTO_INFO struct from the BYTE * key parts. 
// If pubExp info is NULL, use TCG default.
// If there is a remainder while calculating the privExp, return FALSE.

void Crypto_RSABuildCryptoInfoPublic(   /*[IN]*/ UINT32 pubExpSize, 
                                        /*[IN]*/ BYTE *pubExp,
                                        /*[IN]*/ UINT32 modulusSize, 
                                        /*[IN]*/ BYTE *modulus, 
                                        CRYPTO_INFO* cryptoInfo) {
  cryptoInfo->keyInfo = RSA_new();
  RSA *rsa = (RSA *) cryptoInfo->keyInfo;
  
  rsa->e = BN_new();
  
  if (pubExpSize == 0) { // Default e = 2^16+1
    BN_set_bit(rsa->e, 16);
    BN_set_bit(rsa->e, 0);
  } else {
    // This is not supported, but the following line MIGHT work
    // under then assumption that the format is BigNum compatable
    // Though it's not in the spec, so who knows what it is.
    // Forcing the default.
    //BN_bin2bn(pubExp, pubExpSize, NULL);
    BN_set_bit(rsa->e, 16);
    BN_set_bit(rsa->e, 0);
  }
  
  rsa->n = BN_bin2bn(modulus, modulusSize, NULL);
  
}

int Crypto_RSAEnc(  CRYPTO_INFO *key,
		    UINT32 inDataSize,
		    BYTE *inData,
		    /*out*/ UINT32 *outDataSize,
		    /*out*/ BYTE *outData) {
  RSA *rsa = (RSA *) key->keyInfo;
  UINT32 paddedDataSize = RSA_size (rsa);
  BYTE *paddedData = (BYTE *)malloc(sizeof(BYTE) * paddedDataSize);
  int rc;
    
  if (paddedData == NULL) 
    return -1;

  *outDataSize = 0;
  
  switch (key->encScheme) {
  case CRYPTO_ES_RSAESPKCSv15:
    if (RSA_padding_add_PKCS1_type_2(paddedData, paddedDataSize, inData, inDataSize) <= 0) {
      rc = -1; 
      goto abort_egress;
    }
    break;
  case CRYPTO_ES_RSAESOAEP_SHA1_MGF1:
    if (RSA_padding_add_PKCS1_OAEP(paddedData,paddedDataSize,inData,inDataSize, (BYTE *) OAEP_P,OAEP_P_SIZE) <= 0 ) {
      rc = -1; 
      goto abort_egress;
    }
    break;
  default:
    rc = -1; 
    goto abort_egress;
  }
  
  rc = RSA_public_encrypt(paddedDataSize, paddedData, outData, rsa, RSA_NO_PADDING);
  if (rc == -1)
    goto abort_egress; 
   
  *outDataSize = rc;
  
  if (rc > 0) rc = 0;
  
  goto egress;
  
 abort_egress:
 egress:
  
  if (paddedData) 
    free (paddedData);
  return rc;
  
}

int Crypto_RSADec(  CRYPTO_INFO *key,
                    UINT32 inDataSize,
                    BYTE *inData,
                    /*out*/ UINT32 *outDataSize,
                    /*out*/ BYTE *outData) {
  
  RSA *rsa = (RSA *) key->keyInfo;
  UINT32 paddedDataSize = RSA_size (rsa);
  BYTE *paddedData = (BYTE *)malloc(sizeof(BYTE) * paddedDataSize);
  int rc;
  
  if (paddedData == NULL)
    goto abort_egress;
  
  rc = RSA_private_decrypt(inDataSize, inData, paddedData, rsa, RSA_NO_PADDING);
  if (rc == -1) {
    vtpmlogerror(VTPM_LOG_CRYPTO, "RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));
    goto abort_egress;
  }
  
  paddedDataSize = rc;
  
  switch (key->encScheme) {
  case CRYPTO_ES_RSAESPKCSv15:
    rc = RSA_padding_check_PKCS1_type_2 (outData, paddedDataSize,
					 paddedData + 1, paddedDataSize - 1,
					 RSA_size(rsa));
    if (rc == -1) {
      vtpmlogerror(VTPM_LOG_CRYPTO, "RSA_padding_check_PKCS1_type_2: %s\n", 
	      ERR_error_string(ERR_get_error(), NULL));
      goto abort_egress;
    }
    *outDataSize = rc;
    break;
  case CRYPTO_ES_RSAESOAEP_SHA1_MGF1:
    rc = RSA_padding_check_PKCS1_OAEP(outData, paddedDataSize,
				      paddedData + 1, paddedDataSize - 1,
				      RSA_size(rsa),
				      (BYTE *) OAEP_P, OAEP_P_SIZE);
    if (rc == -1) {
      vtpmlogerror(VTPM_LOG_CRYPTO, "RSA_padding_check_PKCS1_OAEP: %s\n",
	      ERR_error_string(ERR_get_error(), NULL));
      goto abort_egress;
    }
    *outDataSize = rc;
    break;
  default:
    *outDataSize = 0;
  }
  
  free(paddedData); paddedData = NULL;
  goto egress;
  
 abort_egress:
  
  if (paddedData) 
    free (paddedData);
  return -1;
  
 egress:
  return 0;
}

// Signs either a SHA1 digest of a message or a DER encoding of a message
// Textual messages MUST be encoded or Hashed before sending into this function
// It will NOT SHA the message.
int Crypto_RSASign( CRYPTO_INFO *key,
                    UINT32 inDataSize,
                    BYTE *inData,
                    /*out*/ UINT32 *sigSize,
                    /*out*/ BYTE *sig) {
  int status;
  unsigned int intSigSize;
  
  switch(key->sigScheme) {
  case CRYPTO_SS_RSASSAPKCS1v15_SHA1: 
    status = RSA_sign(NID_sha1, inData, inDataSize, sig, &intSigSize, (RSA *) key->keyInfo);
    break;
  case CRYPTO_SS_RSASSAPKCS1v15_DER:
    //        status = Crypto_RSA_sign_DER(NID_md5_sha1, inData, inDataSize, sig, &intSigSize, key);
    vtpmlogerror(VTPM_LOG_CRYPTO, "Crypto: Unimplemented sign type (%d)\n", key->sigScheme);
    status = 0;
    break;
  default:
    status = 0;
  }
  
  if (status == 0) {
    *sigSize = 0;
    vtpmlogerror(VTPM_LOG_CRYPTO, "%s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  
  *sigSize = (UINT32) intSigSize;
  return 0;
}

bool Crypto_RSAVerify(  CRYPTO_INFO *key,
                        UINT32 inDataSize,
                        BYTE *inData,
                        UINT32 sigSize,
                        BYTE *sig) {
  int status;
  
  switch(key->sigScheme){
  case CRYPTO_SS_RSASSAPKCS1v15_SHA1: 
    status = RSA_verify(NID_sha1, inData, inDataSize, sig, sigSize, (RSA *) key->keyInfo);
    break;
  case CRYPTO_SS_RSASSAPKCS1v15_DER:
    //status = Crypto_RSA_verify_DER(NID_md5_sha1, inData, inDataSize, sig, sigSize, key);
    vtpmlogerror(VTPM_LOG_CRYPTO, "Crypto: Unimplemented sign type (%d)\n", key->sigScheme);
    status = 0;
    break;
  default:
    status = 0;
  }
  
  if (status) 
    return(1);
  else {
    vtpmlogerror(VTPM_LOG_CRYPTO, "RSA verify: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return(0);
  }
  
}

// helper which packs everything into a BIO!

// packs the parameters first, then the private key, then the public key
// if *io_buf is NULL, allocate it here as needed. otherwise its size is in
// *io_buflen
TPM_RESULT Crypto_RSAPackCryptoInfo (const CRYPTO_INFO* cryptoInfo,
                                      BYTE ** io_buf, UINT32 * io_buflen) {
  TPM_RESULT status = TPM_SUCCESS;
  BYTE * buf;
  long len, outlen = *io_buflen;
  
  const long PARAMSLEN = 3*sizeof(UINT32);
  
  RSA *rsa = (RSA *) cryptoInfo->keyInfo;
  
  BIO *mem = BIO_new(BIO_s_mem());
  
  
  // write the openssl keys to the BIO
  if ( i2d_RSAPrivateKey_bio (mem, rsa) == 0 ) {
    ERR_print_errors_fp (stderr);
    ERRORDIE (TPM_SIZE);
  }
  if ( i2d_RSAPublicKey_bio (mem, rsa) == 0 ) {
    ERR_print_errors_fp (stderr);
    ERRORDIE (TPM_SIZE);
  }
  
  // get the buffer out
  len = BIO_get_mem_data (mem, &buf);
  
  // see if we need to allocate a return buffer
  if (*io_buf == NULL) {
    *io_buf = (BYTE*) malloc (PARAMSLEN + len);
    if (*io_buf == NULL) 
      ERRORDIE (TPM_SIZE);
  } else {                      // *io_buf is already allocated
    if (outlen < len + PARAMSLEN) 
      ERRORDIE (TPM_SIZE); // but not large enough!  
  }
  
  // copy over the parameters (three UINT32's starting at algorithmID)
  memcpy (*io_buf, &cryptoInfo->algorithmID, PARAMSLEN);
  
  // copy over the DER keys
  memcpy (*io_buf + PARAMSLEN, buf, len);
  
  *io_buflen = len + PARAMSLEN;
  
  goto egress;
  
  
 abort_egress:
 egress:
  
  BIO_free (mem);
  
  return status;
}



// sets up ci, and returns the number of bytes read in o_lenread
TPM_RESULT Crypto_RSAUnpackCryptoInfo (CRYPTO_INFO * ci,
                                        BYTE * in, UINT32 len,
                                        UINT32 * o_lenread) {
  
  TPM_RESULT status = TPM_SUCCESS;
  long l;
  BIO *mem;
  RSA *rsa;
  
  // first load up the params
  l = 3 * sizeof(UINT32);
  memcpy (&ci->algorithmID, in, l);
  len -= l;
  in += l;
  
  // and now the openssl keys, private first
  mem = BIO_new_mem_buf (in, len);
  
  if ( (rsa = d2i_RSAPrivateKey_bio (mem, NULL)) == NULL ) {
    ERR_print_errors_fp (stderr);
    ERRORDIE (TPM_BAD_PARAMETER);
  }
  // now use the same RSA object and fill in the private key
  if ( d2i_RSAPublicKey_bio (mem, &rsa) == NULL ) {
    ERR_print_errors_fp (stderr);
    ERRORDIE (TPM_BAD_PARAMETER);
  }
  
  ci->keyInfo = rsa;          // needs to be freed somehow later
  
  // FIXME: havent figured out yet how to tell how many bytes were read in the
  // above oprations! so o_lenread is not set
  
  goto egress;
  
 abort_egress:
 egress:
  
  BIO_free (mem);
 
  return status;  
}
