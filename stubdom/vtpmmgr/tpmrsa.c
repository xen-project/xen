/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
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
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include "tcg.h"
#include "polarssl/sha1.h"

#include <stdlib.h>
#include <stdio.h>

#include "tpmrsa.h"

#define HASH_LEN 20

void tpmrsa_set_pubkey(tpmrsa_context* ctx,
      const unsigned char* key,
      int keylen,
      const unsigned char* exponent,
      int explen) {

   tpmrsa_free(ctx);

   if(explen == 0) { //Default e= 2^16+1
      mpi_lset(&ctx->E, 65537);
   } else {
      mpi_read_binary(&ctx->E, exponent, explen);
   }
   mpi_read_binary(&ctx->N, key, keylen);

   ctx->len = ( mpi_msb(&ctx->N) + 7) >> 3;
}

static TPM_RESULT tpmrsa_public( tpmrsa_context *ctx,
      const unsigned char *input,
      unsigned char *output )
{
   int ret;
   size_t olen;
   mpi T;

   mpi_init( &T );

   MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

   if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
   {
      mpi_free( &T );
      return TPM_ENCRYPT_ERROR;
   }

   olen = ctx->len;
   MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
   MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

   mpi_free( &T );

   if( ret != 0 )
      return TPM_ENCRYPT_ERROR;

   return TPM_SUCCESS;
}

static const unsigned char rsa_der_header[] = {
	0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
};

TPM_RESULT tpmrsa_sigcheck(tpmrsa_context *ctx, const unsigned char *input, const unsigned char *sha1)
{
	unsigned char *tmp = alloca(ctx->len);
	TPM_RESULT rv;
	int i;
	rv = tpmrsa_public(ctx, input, tmp);
	if (rv)
		return rv;
	if (tmp[0] != 0 || tmp[1] != 1)
		return TPM_INAPPROPRIATE_SIG;
	for(i=2; i < 220; i++) {
		if (tmp[i] != 0xFF)
			return TPM_INAPPROPRIATE_SIG;
	}
	if (memcmp(tmp + 220, rsa_der_header, sizeof(rsa_der_header)))
		return TPM_INAPPROPRIATE_SIG;
	if (memcmp(tmp + 236, sha1, 20))
		return TPM_DECRYPT_ERROR;
	return TPM_SUCCESS;
}

static void mgf_mask( unsigned char *dst, int dlen, unsigned char *src, int slen)
{
   unsigned char mask[HASH_LEN];
   unsigned char counter[4] = {0, 0, 0, 0};
   int i;
   sha1_context mctx;

   //We always hash the src with the counter, so save the partial hash
   sha1_starts(&mctx);
   sha1_update(&mctx, src, slen);

   // Generate and apply dbMask
   while(dlen > 0) {
      //Copy the sha1 context
      sha1_context ctx = mctx;

      //compute hash for input || counter
      sha1_update(&ctx, counter, sizeof(counter));
      sha1_finish(&ctx, mask);

      //Apply the mask
      for(i = 0; i < (dlen < HASH_LEN ? dlen : HASH_LEN); ++i) {
         *(dst++) ^= mask[i];
      }

      //Increment counter
      ++counter[3];

      dlen -= HASH_LEN;
   }
}

/*
 * Add the message padding, then do an RSA operation
 */
TPM_RESULT tpmrsa_pub_encrypt_oaep( tpmrsa_context *ctx,
      int (*f_rng)(void *, unsigned char *, size_t),
      void *p_rng,
      size_t ilen,
      const unsigned char *input,
      unsigned char *output )
{
   int ret;
   int olen;
   unsigned char* seed = output + 1;
   unsigned char* db = output + HASH_LEN +1;

   olen = ctx->len-1;

   if( f_rng == NULL )
      return TPM_ENCRYPT_ERROR;

   if( ilen > olen - 2 * HASH_LEN - 1)
      return TPM_ENCRYPT_ERROR;

   output[0] = 0;

   //Encoding parameter p
   sha1((unsigned char*)"TCPA", 4, db);

   //PS
   memset(db + HASH_LEN, 0,
         olen - ilen - 2 * HASH_LEN - 1);

   //constant 1 byte
   db[olen - ilen - HASH_LEN -1] = 0x01;

   //input string
   memcpy(db + olen - ilen - HASH_LEN,
         input, ilen);

   //Generate random seed
   if( ( ret = f_rng( p_rng, seed, HASH_LEN ) ) != 0 )
      return TPM_ENCRYPT_ERROR;

   // maskedDB: Apply dbMask to DB
   mgf_mask( db, olen - HASH_LEN, seed, HASH_LEN);

   // maskedSeed: Apply seedMask to seed
   mgf_mask( seed, HASH_LEN, db, olen - HASH_LEN);

   // Do the crypto op
   return tpmrsa_public(ctx, output, output);
}
