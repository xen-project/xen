/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * THIS SOFTWARE AND ITS DOCUMENTATION ARE PROVIDED AS IS AND WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTIES WHATSOEVER. ALL WARRANTIES
 * INCLUDING, BUT NOT LIMITED TO, PERFORMANCE, MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR  PURPOSE, AND NONINFRINGEMENT ARE HEREBY
 * DISCLAIMED. USERS ASSUME THE ENTIRE RISK AND LIABILITY OF USING THE
 * SOFTWARE.
 */

#include <mini-os/byteorder.h>
#include "vtpmblk.h"
#include "tpm/tpm_marshalling.h"
#include "vtpm_cmd.h"
#include "polarssl/aes.h"
#include "polarssl/sha1.h"
#include <blkfront.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

/*Encryption key and block sizes */
#define BLKSZ 16

static struct blkfront_dev* blkdev = NULL;
static int blkfront_fd = -1;

int init_vtpmblk(struct tpmfront_dev* tpmfront_dev)
{
   struct blkfront_info blkinfo;
   info("Initializing persistent NVM storage\n");

   if((blkdev = init_blkfront(NULL, &blkinfo)) == NULL) {
      error("BLKIO: ERROR Unable to initialize blkfront");
      return -1;
   }
   if (blkinfo.info & VDISK_READONLY || blkinfo.mode != O_RDWR) {
      error("BLKIO: ERROR block device is read only!");
      goto error;
   }
   if((blkfront_fd = blkfront_open(blkdev)) == -1) {
      error("Unable to open blkfront file descriptor!");
      goto error;
   }

   return 0;
error:
   shutdown_blkfront(blkdev);
   blkdev = NULL;
   return -1;
}

void shutdown_vtpmblk(void)
{
   close(blkfront_fd);
   blkfront_fd = -1;
   blkdev = NULL;
}

int write_vtpmblk_raw(uint8_t *data, size_t data_length)
{
   int rc;
   uint32_t lenbuf;
   debug("Begin Write data=%p len=%u", data, data_length);

   lenbuf = cpu_to_be32((uint32_t)data_length);

   lseek(blkfront_fd, 0, SEEK_SET);
   if((rc = write(blkfront_fd, (uint8_t*)&lenbuf, 4)) != 4) {
      error("write(length) failed! error was %s", strerror(errno));
      return -1;
   }
   if((rc = write(blkfront_fd, data, data_length)) != data_length) {
      error("write(data) failed! error was %s", strerror(errno));
      return -1;
   }

   info("Wrote %u bytes to NVM persistent storage", data_length);

   return 0;
}

int read_vtpmblk_raw(uint8_t **data, size_t *data_length)
{
   int rc;
   uint32_t lenbuf;

   lseek(blkfront_fd, 0, SEEK_SET);
   if(( rc = read(blkfront_fd, (uint8_t*)&lenbuf, 4)) != 4) {
      error("read(length) failed! error was %s", strerror(errno));
      return -1;
   }
   *data_length = (size_t) cpu_to_be32(lenbuf);
   if(*data_length == 0) {
      error("read 0 data_length for NVM");
      return -1;
   }

   *data = tpm_malloc(*data_length);
   if((rc = read(blkfront_fd, *data, *data_length)) != *data_length) {
      error("read(data) failed! error was %s", strerror(errno));
      return -1;
   }

   info("Read %u bytes from NVM persistent storage", *data_length);
   return 0;
}

int encrypt_vtpmblk(uint8_t* clear, size_t clear_len, uint8_t** cipher, size_t* cipher_len, uint8_t* symkey)
{
   int rc = 0;
   uint8_t iv[BLKSZ];
   aes_context aes_ctx;
   UINT32 temp;
   int mod;

   uint8_t* clbuf = NULL;

   uint8_t* ivptr;
   int ivlen;

   uint8_t* cptr;	//Cipher block pointer
   int clen;	//Cipher block length

   /*Create a new 256 bit encryption key */
   if(symkey == NULL) {
      rc = -1;
      goto abort_egress;
   }
   tpm_get_extern_random_bytes(symkey, NVMKEYSZ);

   /*Setup initialization vector - random bits and then 4 bytes clear text size at the end*/
   temp = sizeof(UINT32);
   ivlen = BLKSZ - temp;
   tpm_get_extern_random_bytes(iv, ivlen);
   ivptr = iv + ivlen;
   tpm_marshal_UINT32(&ivptr, &temp, (UINT32) clear_len);

   /*The clear text needs to be padded out to a multiple of BLKSZ */
   mod = clear_len % BLKSZ;
   clen = mod ? clear_len + BLKSZ - mod : clear_len;
   clbuf = malloc(clen);
   if (clbuf == NULL) {
      rc = -1;
      goto abort_egress;
   }
   memcpy(clbuf, clear, clear_len);
   /* zero out the padding bits - FIXME: better / more secure way to handle these? */
   if(clen - clear_len) {
      memset(clbuf + clear_len, 0, clen - clear_len);
   }

   /* Setup the ciphertext buffer */
   *cipher_len = BLKSZ + clen;		/*iv + ciphertext */
   cptr = *cipher = malloc(*cipher_len);
   if (*cipher == NULL) {
      rc = -1;
      goto abort_egress;
   }

   /* Copy the IV to cipher text blob*/
   memcpy(cptr, iv, BLKSZ);
   cptr += BLKSZ;

   /* Setup encryption */
   aes_setkey_enc(&aes_ctx, symkey, 256);

   /* Do encryption now */
   aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, clen, iv, clbuf, cptr);

   goto egress;
abort_egress:
egress:
   free(clbuf);
   return rc;
}
int decrypt_vtpmblk(uint8_t* cipher, size_t cipher_len, uint8_t** clear, size_t* clear_len, uint8_t* symkey)
{
   int rc = 0;
   uint8_t iv[BLKSZ];
   uint8_t* ivptr;
   UINT32 u32, temp;
   aes_context aes_ctx;

   uint8_t* cptr = cipher;	//cipher block pointer
   int clen = cipher_len;	//cipher block length

   /* Pull out the initialization vector */
   memcpy(iv, cipher, BLKSZ);
   cptr += BLKSZ;
   clen -= BLKSZ;

   /* Setup the clear text buffer */
   if((*clear = malloc(clen)) == NULL) {
      rc = -1;
      goto abort_egress;
   }

   /* Get the length of clear text from last 4 bytes of iv */
   temp = sizeof(UINT32);
   ivptr = iv + BLKSZ - temp;
   tpm_unmarshal_UINT32(&ivptr, &temp, &u32);
   *clear_len = u32;

   /* Setup decryption */
   aes_setkey_dec(&aes_ctx, symkey, 256);

   /* Do decryption now */
   if ((clen % BLKSZ) != 0) {
      error("Decryption Error: Cipher block size was not a multiple of %u", BLKSZ);
      rc = -1;
      goto abort_egress;
   }
   aes_crypt_cbc(&aes_ctx, AES_DECRYPT, clen, iv, cptr, *clear);

   goto egress;
abort_egress:
egress:
   return rc;
}

int write_vtpmblk(struct tpmfront_dev* tpmfront_dev, uint8_t* data, size_t data_length) {
   int rc;
   uint8_t* cipher = NULL;
   size_t cipher_len = 0;
   uint8_t hashkey[HASHKEYSZ];
   uint8_t* symkey = hashkey + HASHSZ;

   /* Encrypt the data */
   if((rc = encrypt_vtpmblk(data, data_length, &cipher, &cipher_len, symkey))) {
      goto abort_egress;
   }
   /* Write to disk */
   if((rc = write_vtpmblk_raw(cipher, cipher_len))) {
      goto abort_egress;
   }
   /* Get sha1 hash of data */
   sha1(cipher, cipher_len, hashkey);

   /* Send hash and key to manager */
   if((rc = VTPM_SaveHashKey(tpmfront_dev, hashkey, HASHKEYSZ)) != TPM_SUCCESS) {
      goto abort_egress;
   }
   goto egress;
abort_egress:
egress:
   free(cipher);
   return rc;
}

int read_vtpmblk(struct tpmfront_dev* tpmfront_dev, uint8_t** data, size_t *data_length) {
   int rc;
   uint8_t* cipher = NULL;
   size_t cipher_len = 0;
   size_t keysize;
   uint8_t* hashkey = NULL;
   uint8_t hash[HASHSZ];
   uint8_t* symkey;

   /* Retreive the hash and the key from the manager */
   if((rc = VTPM_LoadHashKey(tpmfront_dev, &hashkey, &keysize)) != TPM_SUCCESS) {
      goto abort_egress;
   }
   if(keysize != HASHKEYSZ) {
      error("Manager returned a hashkey of invalid size! expected %d, actual %d", NVMKEYSZ, keysize);
      rc = -1;
      goto abort_egress;
   }
   symkey = hashkey + HASHSZ;

   /* Read from disk now */
   if((rc = read_vtpmblk_raw(&cipher, &cipher_len))) {
      goto abort_egress;
   }

   /* Compute the hash of the cipher text and compare */
   sha1(cipher, cipher_len, hash);
   if(memcmp(hash, hashkey, HASHSZ)) {
      int i;
      error("NVM Storage Checksum failed!");
      printf("Expected: ");
      for(i = 0; i < HASHSZ; ++i) {
	 printf("%02hhX ", hashkey[i]);
      }
      printf("\n");
      printf("Actual:   ");
      for(i = 0; i < HASHSZ; ++i) {
	 printf("%02hhX ", hash[i]);
      }
      printf("\n");
      rc = -1;
      goto abort_egress;
   }

   /* Decrypt the blob */
   if((rc = decrypt_vtpmblk(cipher, cipher_len, data, data_length, symkey))) {
      goto abort_egress;
   }
   goto egress;
abort_egress:
egress:
   free(cipher);
   free(hashkey);
   return rc;
}
