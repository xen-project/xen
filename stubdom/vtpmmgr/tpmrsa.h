/**
 * \file rsa.h
 *
 * \brief The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef TPMRSA_H
#define TPMRSA_H

#include "tcg.h"
#include <polarssl/bignum.h>

/* tpm software key */
typedef struct
{
    size_t len;                 /*!<  size(N) in chars  */

    mpi N;                      /*!<  public modulus    */
    mpi E;                      /*!<  public exponent   */

    mpi RN;                     /*!<  cached R^2 mod N  */
}
tpmrsa_context;

#define TPMRSA_CTX_INIT { 0, {0, 0, NULL}, {0, 0, NULL}, {0, 0, NULL}}

/* Setup the rsa context using tpm public key data */
void tpmrsa_set_pubkey(tpmrsa_context* ctx,
      const unsigned char* key,
      int keylen,
      const unsigned char* exponent,
      int explen);

/* Check an RSA signature */
TPM_RESULT tpmrsa_sigcheck(tpmrsa_context *ctx, const unsigned char *input, const unsigned char *sha1);

/* Do rsa public crypto */
TPM_RESULT tpmrsa_pub_encrypt_oaep( tpmrsa_context *ctx,
      int (*f_rng)(void *, unsigned char *, size_t),
      void *p_rng,
      size_t ilen,
      const unsigned char *input,
      unsigned char *output );

/* free tpmrsa key */
inline void tpmrsa_free( tpmrsa_context *ctx ) {
   mpi_free( &ctx->RN ); mpi_free( &ctx->E  ); mpi_free( &ctx->N  );
}

#endif /* tpmrsa.h */
