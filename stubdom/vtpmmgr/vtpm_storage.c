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

/***************************************************************
 * DISK IMAGE LAYOUT
 * *************************************************************
 * All data is stored in BIG ENDIAN format
 * *************************************************************
 * Section 1: Header
 *
 * 10 bytes 	 id			ID String "VTPMMGRDOM"
 * uint32_t	 version	        Disk Image version number (current == 1)
 * uint32_t      storage_key_len	Length of the storage Key
 * TPM_KEY       storage_key		Marshalled TPM_KEY structure (See TPM spec v2)
 * RSA_BLOCK     aes_crypto             Encrypted aes key data (RSA_CIPHER_SIZE bytes), bound by the storage_key
 *  BYTE[32] aes_key                    Aes key for encrypting the uuid table
 *  uint32_t cipher_sz                  Encrypted size of the uuid table
 *
 * *************************************************************
 * Section 2: Uuid Table
 *
 * This table is encrypted by the aes_key in the header. The cipher text size is just
 * large enough to hold all of the entries plus required padding.
 *
 * Each entry is as follows
 * BYTE[16] uuid                       Uuid of a vtpm that is stored on this disk
 * uint32_t offset                     Disk offset where the vtpm data is stored
 *
 * *************************************************************
 * Section 3: Vtpm Table
 *
 * The rest of the disk stores vtpms. Each vtpm is an RSA_BLOCK encrypted
 * by the storage key. Each vtpm must exist on an RSA_BLOCK aligned boundary,
 * starting at the first RSA_BLOCK aligned offset after the uuid table.
 * As the uuid table grows, vtpms may be relocated.
 *
 * RSA_BLOCK     vtpm_crypto          Vtpm data encrypted by storage_key
 *   BYTE[20]    hash                 Sha1 hash of vtpm encrypted data
 *   BYTE[16]    vtpm_aes_key         Encryption key for vtpm data
 *
  *************************************************************
 */
#define DISKVERS 1
#define IDSTR "VTPMMGRDOM"
#define IDSTRLEN 10
#define AES_BLOCK_SIZE 16
#define AES_KEY_BITS 256
#define AES_KEY_SIZE (AES_KEY_BITS/8)
#define BUF_SIZE 4096

#define UUID_TBL_ENT_SIZE (sizeof(uuid_t) + sizeof(uint32_t))

#define HEADERSZ (10 + 4 + 4)

#define TRY_READ(buf, size, msg) do {\
   int rc; \
   if((rc = read(blkfront_fd, buf, (size))) != (size)) { \
      vtpmlogerror(VTPM_LOG_VTPM, "read() failed! " msg " : rc=(%d/%d), error=(%s)\n", rc, (int)(size), strerror(errno)); \
      status = TPM_IOERROR;\
      goto abort_egress;\
   } \
} while(0)

#define TRY_WRITE(buf, size, msg) do {\
   int rc; \
   if((rc = write(blkfront_fd, buf, (size))) != (size)) { \
      vtpmlogerror(VTPM_LOG_VTPM, "write() failed! " msg " : rc=(%d/%d), error=(%s)\n", rc, (int)(size), strerror(errno)); \
      status = TPM_IOERROR;\
      goto abort_egress;\
   } \
} while(0)

#include <blkfront.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mini-os/byteorder.h>
#include <polarssl/aes.h>

#include "vtpm_manager.h"
#include "log.h"
#include "marshal.h"
#include "tpm.h"
#include "uuid.h"

#include "vtpmmgr.h"
#include "vtpm_storage.h"

#define MAX(a,b) ( ((a) > (b)) ? (a) : (b) )
#define MIN(a,b) ( ((a) < (b)) ? (a) : (b) )

/* blkfront device objets */
static struct blkfront_dev* blkdev = NULL;
static int blkfront_fd = -1;

struct Vtpm {
   uuid_t uuid;
   int offset;
};
struct Storage {
   int aes_offset;
   int uuid_offset;
   int end_offset;

   int num_vtpms;
   int num_vtpms_alloced;
   struct Vtpm* vtpms;
};

/* Global storage data */
static struct Storage g_store = {
   .vtpms = NULL,
};

static int get_offset(void) {
   return lseek(blkfront_fd, 0, SEEK_CUR);
}

static void reset_store(void) {
   g_store.aes_offset = 0;
   g_store.uuid_offset = 0;
   g_store.end_offset = 0;

   g_store.num_vtpms = 0;
   g_store.num_vtpms_alloced = 0;
   free(g_store.vtpms);
   g_store.vtpms = NULL;
}

static int vtpm_get_index(const uuid_t uuid) {
   int st = 0;
   int ed = g_store.num_vtpms-1;
   while(st <= ed) {
      int mid = ((unsigned int)st + (unsigned int)ed) >> 1; //avoid overflow
      int c = memcmp(uuid, &g_store.vtpms[mid].uuid, sizeof(uuid_t));
      if(c == 0) {
         return mid;
      } else if(c > 0) {
         st = mid + 1;
      } else {
         ed = mid - 1;
      }
   }
   return -(st + 1);
}

static void vtpm_add(const uuid_t uuid, int offset, int index) {
   /* Realloc more space if needed */
   if(g_store.num_vtpms >= g_store.num_vtpms_alloced) {
      g_store.num_vtpms_alloced += 16;
      g_store.vtpms = realloc(
            g_store.vtpms,
            sizeof(struct Vtpm) * g_store.num_vtpms_alloced);
   }

   /* Move everybody after the new guy */
   for(int i = g_store.num_vtpms; i > index; --i) {
      g_store.vtpms[i] = g_store.vtpms[i-1];
   }

   vtpmloginfo(VTPM_LOG_VTPM, "Registered vtpm " UUID_FMT "\n", UUID_BYTES(uuid));

   /* Finally add new one */
   memcpy(g_store.vtpms[index].uuid, uuid, sizeof(uuid_t));
   g_store.vtpms[index].offset = offset;
   ++g_store.num_vtpms;
}

#if 0
static void vtpm_remove(int index) {
   for(i = index; i < g_store.num_vtpms; ++i) {
      g_store.vtpms[i] = g_store.vtpms[i+1];
   }
   --g_store.num_vtpms;
}
#endif

static int pack_uuid_table(uint8_t* table, int size, int* nvtpms) {
   uint8_t* ptr = table;
   while(*nvtpms < g_store.num_vtpms && size >= 0)
   {
      /* Pack the uuid */
      memcpy(ptr, (uint8_t*)g_store.vtpms[*nvtpms].uuid, sizeof(uuid_t));
      ptr+= sizeof(uuid_t);


      /* Pack the offset */
      ptr = pack_UINT32(ptr, g_store.vtpms[*nvtpms].offset);

      ++*nvtpms;
      size -= UUID_TBL_ENT_SIZE;
   }
   return ptr - table;
}

/* Extract the uuids */
static int extract_uuid_table(uint8_t* table, int size) {
   uint8_t* ptr = table;
   for(;size >= UUID_TBL_ENT_SIZE; size -= UUID_TBL_ENT_SIZE) {
      int index;
      uint32_t v32;

      /*uuid_t is just an array of bytes, so we can do a direct cast here */
      uint8_t* uuid = ptr;
      ptr += sizeof(uuid_t);

      /* Get the offset of the key */
      ptr = unpack_UINT32(ptr, &v32);

      /* Insert the new vtpm in sorted order */
      if((index = vtpm_get_index(uuid)) >= 0) {
         vtpmlogerror(VTPM_LOG_VTPM, "Vtpm (" UUID_FMT ") exists multiple times! ignoring...\n", UUID_BYTES(uuid));
         continue;
      }
      index = -index -1;

      vtpm_add(uuid, v32, index);

   }
   return ptr - table;
}

static void vtpm_decrypt_block(aes_context* aes,
      uint8_t* iv,
      uint8_t* cipher,
      uint8_t* plain,
      int cipher_sz,
      int* overlap)
{
   int bytes_ext;
   /* Decrypt */
   aes_crypt_cbc(aes, AES_DECRYPT,
         cipher_sz,
         iv, cipher, plain + *overlap);

   /* Extract */
   bytes_ext = extract_uuid_table(plain, cipher_sz + *overlap);

   /* Copy left overs to the beginning */
   *overlap = cipher_sz + *overlap - bytes_ext;
   memcpy(plain, plain + bytes_ext, *overlap);
}

static int vtpm_encrypt_block(aes_context* aes,
      uint8_t* iv,
      uint8_t* plain,
      uint8_t* cipher,
      int block_sz,
      int* overlap,
      int* num_vtpms)
{
   int bytes_to_crypt;
   int bytes_packed;

   /* Pack the uuid table */
   bytes_packed = *overlap + pack_uuid_table(plain + *overlap, block_sz - *overlap, num_vtpms);
   bytes_to_crypt = MIN(bytes_packed, block_sz);

   /* Add padding if we aren't on a multiple of the block size */
   if(bytes_to_crypt & (AES_BLOCK_SIZE-1)) {
      int oldsz = bytes_to_crypt;
      //add padding
      bytes_to_crypt += AES_BLOCK_SIZE - (bytes_to_crypt & (AES_BLOCK_SIZE-1));
      //fill padding with random bytes
      vtpmmgr_rand(plain + oldsz, bytes_to_crypt - oldsz);
      *overlap = 0;
   } else {
      *overlap = bytes_packed - bytes_to_crypt;
   }

   /* Encrypt this chunk */
   aes_crypt_cbc(aes, AES_ENCRYPT,
            bytes_to_crypt,
            iv, plain, cipher);

   /* Copy the left over partials to the beginning */
   memcpy(plain, plain + bytes_to_crypt, *overlap);

   return bytes_to_crypt;
}

static TPM_RESULT vtpm_storage_new_vtpm(const uuid_t uuid, int index) {
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t plain[BUF_SIZE + AES_BLOCK_SIZE];
   uint8_t buf[BUF_SIZE];
   uint8_t* ptr;
   int cipher_sz;
   aes_context aes;

   /* Add new vtpm to the table */
   vtpm_add(uuid, g_store.end_offset, index);
   g_store.end_offset += RSA_CIPHER_SIZE;

   /* Compute the new end location of the encrypted uuid table */
   cipher_sz = AES_BLOCK_SIZE; //IV
   cipher_sz += g_store.num_vtpms * UUID_TBL_ENT_SIZE; //uuid table
   cipher_sz += (AES_BLOCK_SIZE - (cipher_sz & (AES_BLOCK_SIZE -1))) & (AES_BLOCK_SIZE-1); //aes padding

   /* Does this overlap any key data? If so they need to be relocated */
   int uuid_end = (g_store.uuid_offset + cipher_sz + RSA_CIPHER_SIZE) & ~(RSA_CIPHER_SIZE -1);
   for(int i = 0; i < g_store.num_vtpms; ++i) {
      if(g_store.vtpms[i].offset < uuid_end) {

         vtpmloginfo(VTPM_LOG_VTPM, "Relocating vtpm data\n");

         //Read the hashkey cipher text
         lseek(blkfront_fd, g_store.vtpms[i].offset, SEEK_SET);
         TRY_READ(buf, RSA_CIPHER_SIZE, "vtpm hashkey relocate");

         //Write the cipher text to new offset
         lseek(blkfront_fd, g_store.end_offset, SEEK_SET);
         TRY_WRITE(buf, RSA_CIPHER_SIZE, "vtpm hashkey relocate");

         //Save new offset
         g_store.vtpms[i].offset = g_store.end_offset;
         g_store.end_offset += RSA_CIPHER_SIZE;
      }
   }

   vtpmloginfo(VTPM_LOG_VTPM, "Generating a new symmetric key\n");

   /* Generate an aes key */
   TPMTRYRETURN(vtpmmgr_rand(plain, AES_KEY_SIZE));
   aes_setkey_enc(&aes, plain, AES_KEY_BITS);
   ptr = plain + AES_KEY_SIZE;

   /* Pack the crypted size */
   ptr = pack_UINT32(ptr, cipher_sz);

   vtpmloginfo(VTPM_LOG_VTPM, "Binding encrypted key\n");

   /* Seal the key and size */
   TPMTRYRETURN(TPM_Bind(&vtpm_globals.storage_key,
            plain,
            ptr - plain,
            buf));

   /* Write the sealed key to disk */
   lseek(blkfront_fd, g_store.aes_offset, SEEK_SET);
   TRY_WRITE(buf, RSA_CIPHER_SIZE, "vtpm aes key");

   /* ENCRYPT AND WRITE UUID TABLE */

   vtpmloginfo(VTPM_LOG_VTPM, "Encrypting the uuid table\n");

   int num_vtpms = 0;
   int overlap = 0;
   int bytes_crypted;
   uint8_t iv[AES_BLOCK_SIZE];

   /* Generate the iv for the first block */
   TPMTRYRETURN(vtpmmgr_rand(iv, AES_BLOCK_SIZE));

   /* Copy the iv to the cipher text buffer to be written to disk */
   memcpy(buf, iv, AES_BLOCK_SIZE);
   ptr = buf + AES_BLOCK_SIZE;

   /* Encrypt the first block of the uuid table */
   bytes_crypted = vtpm_encrypt_block(&aes,
         iv, //iv
         plain, //plaintext
         ptr, //cipher text
         BUF_SIZE - AES_BLOCK_SIZE,
         &overlap,
         &num_vtpms);

   /* Write the iv followed by the crypted table*/
   TRY_WRITE(buf, bytes_crypted + AES_BLOCK_SIZE, "vtpm uuid table");

   /* Decrement the number of bytes encrypted */
   cipher_sz -= bytes_crypted + AES_BLOCK_SIZE;

   /* If there are more vtpms, encrypt and write them block by block */
   while(cipher_sz > 0) {
      /* Encrypt the next block of the uuid table */
      bytes_crypted = vtpm_encrypt_block(&aes,
               iv,
               plain,
               buf,
               BUF_SIZE,
               &overlap,
               &num_vtpms);

      /* Write the cipher text to disk */
      TRY_WRITE(buf, bytes_crypted, "vtpm uuid table");

      cipher_sz -= bytes_crypted;
   }

   goto egress;
abort_egress:
egress:
   return status;
}


/**************************************
 * PUBLIC FUNCTIONS
 * ***********************************/

int vtpm_storage_init(void) {
   struct blkfront_info info;
   if((blkdev = init_blkfront(NULL, &info)) == NULL) {
      return -1;
   }
   if((blkfront_fd = blkfront_open(blkdev)) < 0) {
      return -1;
   }
   return 0;
}

void vtpm_storage_shutdown(void) {
   reset_store();
   close(blkfront_fd);
}

TPM_RESULT vtpm_storage_load_hashkey(const uuid_t uuid, uint8_t hashkey[HASHKEYSZ])
{
   TPM_RESULT status = TPM_SUCCESS;
   int index;
   uint8_t cipher[RSA_CIPHER_SIZE];
   uint8_t clear[RSA_CIPHER_SIZE];
   UINT32 clear_size;

   /* Find the index of this uuid */
   if((index = vtpm_get_index(uuid)) < 0) {
      index = -index-1;
      vtpmlogerror(VTPM_LOG_VTPM, "LoadKey failure: Unrecognized uuid! " UUID_FMT "\n", UUID_BYTES(uuid));
      status = TPM_BAD_PARAMETER;
      goto abort_egress;
   }

   /* Read the table entry */
   lseek(blkfront_fd, g_store.vtpms[index].offset, SEEK_SET);
   TRY_READ(cipher, RSA_CIPHER_SIZE, "vtpm hashkey data");

   /* Decrypt the table entry */
   TPMTRYRETURN(TPM_UnBind(
            vtpm_globals.storage_key_handle,
            RSA_CIPHER_SIZE,
            cipher,
            &clear_size,
            clear,
            (const TPM_AUTHDATA*)&vtpm_globals.storage_key_usage_auth,
            &vtpm_globals.oiap));

   if(clear_size < HASHKEYSZ) {
      vtpmloginfo(VTPM_LOG_VTPM, "Decrypted Hash key size (%" PRIu32 ") was too small!\n", clear_size);
      status = TPM_RESOURCES;
      goto abort_egress;
   }

   memcpy(hashkey, clear, HASHKEYSZ);

   vtpmloginfo(VTPM_LOG_VTPM, "Loaded hash and key for vtpm " UUID_FMT "\n", UUID_BYTES(uuid));
   goto egress;
abort_egress:
   vtpmlogerror(VTPM_LOG_VTPM, "Failed to load key\n");
egress:
   return status;
}

TPM_RESULT vtpm_storage_save_hashkey(const uuid_t uuid, uint8_t hashkey[HASHKEYSZ])
{
   TPM_RESULT status = TPM_SUCCESS;
   int index;
   uint8_t buf[RSA_CIPHER_SIZE];

   /* Find the index of this uuid */
   if((index = vtpm_get_index(uuid)) < 0) {
      index = -index-1;
      /* Create a new vtpm */
      TPMTRYRETURN( vtpm_storage_new_vtpm(uuid, index) );
   }

   /* Encrypt the hash and key */
   TPMTRYRETURN( TPM_Bind(&vtpm_globals.storage_key,
            hashkey,
            HASHKEYSZ,
            buf));

   /* Write to disk */
   lseek(blkfront_fd, g_store.vtpms[index].offset, SEEK_SET);
   TRY_WRITE(buf, RSA_CIPHER_SIZE, "vtpm hashkey data");

   vtpmloginfo(VTPM_LOG_VTPM, "Saved hash and key for vtpm " UUID_FMT "\n", UUID_BYTES(uuid));
   goto egress;
abort_egress:
   vtpmlogerror(VTPM_LOG_VTPM, "Failed to save key\n");
egress:
   return status;
}

TPM_RESULT vtpm_storage_new_header()
{
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t buf[BUF_SIZE];
   uint8_t keybuf[AES_KEY_SIZE + sizeof(uint32_t)];
   uint8_t* ptr = buf;
   uint8_t* sptr;

   /* Clear everything first */
   reset_store();

   vtpmloginfo(VTPM_LOG_VTPM, "Creating new disk image header\n");

   /*Copy the ID string */
   memcpy(ptr, IDSTR, IDSTRLEN);
   ptr += IDSTRLEN;

   /*Copy the version */
   ptr = pack_UINT32(ptr, DISKVERS);

   /*Save the location of the key size */
   sptr = ptr;
   ptr += sizeof(UINT32);

   vtpmloginfo(VTPM_LOG_VTPM, "Saving root storage key..\n");

   /* Copy the storage key */
   ptr = pack_TPM_KEY(ptr, &vtpm_globals.storage_key);

   /* Now save the size */
   pack_UINT32(sptr, ptr - (sptr + 4));

   /* Create a fake aes key and set cipher text size to 0 */
   memset(keybuf, 0, sizeof(keybuf));

   vtpmloginfo(VTPM_LOG_VTPM, "Binding uuid table symmetric key..\n");

   /* Save the location of the aes key */
   g_store.aes_offset = ptr - buf;

   /* Store the fake aes key and vtpm count */
   TPMTRYRETURN(TPM_Bind(&vtpm_globals.storage_key,
         keybuf,
         sizeof(keybuf),
         ptr));
   ptr+= RSA_CIPHER_SIZE;

   /* Write the header to disk */
   lseek(blkfront_fd, 0, SEEK_SET);
   TRY_WRITE(buf, ptr-buf, "vtpm header");

   /* Save the location of the uuid table */
   g_store.uuid_offset = get_offset();

   /* Save the end offset */
   g_store.end_offset = (g_store.uuid_offset + RSA_CIPHER_SIZE) & ~(RSA_CIPHER_SIZE -1);

   vtpmloginfo(VTPM_LOG_VTPM, "Saved new manager disk header.\n");

   goto egress;
abort_egress:
egress:
   return status;
}


TPM_RESULT vtpm_storage_load_header(void)
{
   TPM_RESULT status = TPM_SUCCESS;
   uint32_t v32;
   uint8_t buf[BUF_SIZE];
   uint8_t* ptr = buf;
   aes_context aes;

   /* Clear everything first */
   reset_store();

   /* Read the header from disk */
   lseek(blkfront_fd, 0, SEEK_SET);
   TRY_READ(buf, IDSTRLEN + sizeof(UINT32) + sizeof(UINT32), "vtpm header");

   vtpmloginfo(VTPM_LOG_VTPM, "Loading disk image header\n");

   /* Verify the ID string */
   if(memcmp(ptr, IDSTR, IDSTRLEN)) {
      vtpmlogerror(VTPM_LOG_VTPM, "Invalid ID string in disk image!\n");
      status = TPM_FAIL;
      goto abort_egress;
   }
   ptr+=IDSTRLEN;

   /* Unpack the version */
   ptr = unpack_UINT32(ptr, &v32);

   /* Verify the version */
   if(v32 != DISKVERS) {
      vtpmlogerror(VTPM_LOG_VTPM, "Unsupported disk image version number %" PRIu32 "\n", v32);
      status = TPM_FAIL;
      goto abort_egress;
   }

   /* Size of the storage key */
   ptr = unpack_UINT32(ptr, &v32);

   /* Sanity check */
   if(v32 > BUF_SIZE) {
      vtpmlogerror(VTPM_LOG_VTPM, "Size of storage key (%" PRIu32 ") is too large!\n", v32);
      status = TPM_IOERROR;
      goto abort_egress;
   }

   /* read the storage key */
   TRY_READ(buf, v32, "storage pub key");

   vtpmloginfo(VTPM_LOG_VTPM, "Unpacking storage key\n");

   /* unpack the storage key */
   ptr = unpack_TPM_KEY(buf, &vtpm_globals.storage_key, UNPACK_ALLOC);

   /* Load Storage Key into the TPM */
   TPMTRYRETURN( TPM_LoadKey(
            TPM_SRK_KEYHANDLE,
            &vtpm_globals.storage_key,
            &vtpm_globals.storage_key_handle,
            (const TPM_AUTHDATA*)&vtpm_globals.srk_auth,
            &vtpm_globals.oiap));

   /* Initialize the storage key auth */
   memset(vtpm_globals.storage_key_usage_auth, 0, sizeof(TPM_AUTHDATA));

   /* Store the offset of the aes key */
   g_store.aes_offset = get_offset();

   /* Read the rsa cipher text for the aes key */
   TRY_READ(buf, RSA_CIPHER_SIZE, "aes key");
   ptr = buf + RSA_CIPHER_SIZE;

   vtpmloginfo(VTPM_LOG_VTPM, "Unbinding uuid table symmetric key\n");

   /* Decrypt the aes key protecting the uuid table */
   UINT32 datalen;
   TPMTRYRETURN(TPM_UnBind(
            vtpm_globals.storage_key_handle,
            RSA_CIPHER_SIZE,
            buf,
            &datalen,
            ptr,
            (const TPM_AUTHDATA*)&vtpm_globals.storage_key_usage_auth,
            &vtpm_globals.oiap));

   /* Validate the length of the output buffer */
   if(datalen < AES_KEY_SIZE + sizeof(UINT32)) {
      vtpmlogerror(VTPM_LOG_VTPM, "Unbound AES key size (%d) was too small! expected (%zu)\n", datalen, AES_KEY_SIZE + sizeof(UINT32));
      status = TPM_IOERROR;
      goto abort_egress;
   }

   /* Extract the aes key */
   aes_setkey_dec(&aes, ptr, AES_KEY_BITS);
   ptr+= AES_KEY_SIZE;

   /* Extract the ciphertext size */
   ptr = unpack_UINT32(ptr, &v32);
   int cipher_size = v32;

   /* Sanity check */
   if(cipher_size & (AES_BLOCK_SIZE-1)) {
      vtpmlogerror(VTPM_LOG_VTPM, "Cipher text size (%" PRIu32 ") is not a multiple of the aes block size! (%d)\n", v32, AES_BLOCK_SIZE);
      status = TPM_IOERROR;
      goto abort_egress;
   }

   /* Save the location of the uuid table */
   g_store.uuid_offset = get_offset();

   /* Only decrypt the table if there are vtpms to decrypt */
   if(cipher_size > 0) {
      int rbytes;
      int overlap = 0;
      uint8_t plain[BUF_SIZE + AES_BLOCK_SIZE];
      uint8_t iv[AES_BLOCK_SIZE];

      vtpmloginfo(VTPM_LOG_VTPM, "Decrypting uuid table\n");

      /* Pre allocate the vtpm array */
      g_store.num_vtpms_alloced = cipher_size / UUID_TBL_ENT_SIZE;
      g_store.vtpms = malloc(sizeof(struct Vtpm) * g_store.num_vtpms_alloced);

      /* Read the iv and the first chunk of cipher text */
      rbytes = MIN(cipher_size, BUF_SIZE);
      TRY_READ(buf, rbytes, "vtpm uuid table\n");
      cipher_size -= rbytes;

      /* Copy the iv */
      memcpy(iv, buf, AES_BLOCK_SIZE);
      ptr = buf + AES_BLOCK_SIZE;

      /* Remove the iv from the number of bytes to decrypt */
      rbytes -= AES_BLOCK_SIZE;

      /* Decrypt and extract vtpms */
      vtpm_decrypt_block(&aes,
            iv, ptr, plain,
            rbytes, &overlap);

      /* Read the rest of the table if there is more */
      while(cipher_size > 0) {
         /* Read next chunk of cipher text */
         rbytes = MIN(cipher_size, BUF_SIZE);
         TRY_READ(buf, rbytes, "vtpm uuid table");
         cipher_size -= rbytes;

         /* Decrypt a block of text */
         vtpm_decrypt_block(&aes,
               iv, buf, plain,
               rbytes, &overlap);

      }
      vtpmloginfo(VTPM_LOG_VTPM, "Loaded %d vtpms!\n", g_store.num_vtpms);
   }

   /* The end of the key table, new vtpms go here */
   int uuid_end = (get_offset() + RSA_CIPHER_SIZE) & ~(RSA_CIPHER_SIZE -1);
   g_store.end_offset = uuid_end;

   /* Compute the end offset while validating vtpms*/
   for(int i = 0; i < g_store.num_vtpms; ++i) {
      /* offset must not collide with previous data */
      if(g_store.vtpms[i].offset < uuid_end) {
         vtpmlogerror(VTPM_LOG_VTPM, "vtpm: " UUID_FMT
               " offset (%d) is before end of uuid table (%d)!\n",
               UUID_BYTES(g_store.vtpms[i].uuid),
               g_store.vtpms[i].offset, uuid_end);
         status = TPM_IOERROR;
         goto abort_egress;
      }
      /* offset must be at a multiple of cipher size */
      if(g_store.vtpms[i].offset & (RSA_CIPHER_SIZE-1)) {
         vtpmlogerror(VTPM_LOG_VTPM, "vtpm: " UUID_FMT
               " offset(%d) is not at a multiple of the rsa cipher text size (%d)!\n",
               UUID_BYTES(g_store.vtpms[i].uuid),
               g_store.vtpms[i].offset, RSA_CIPHER_SIZE);
         status = TPM_IOERROR;
         goto abort_egress;
      }
      /* Save the last offset */
      if(g_store.vtpms[i].offset >= g_store.end_offset) {
         g_store.end_offset = g_store.vtpms[i].offset + RSA_CIPHER_SIZE;
      }
   }

   goto egress;
abort_egress:
   //An error occured somewhere
   vtpmlogerror(VTPM_LOG_VTPM, "Failed to load manager data!\n");

   //Clear the data store
   reset_store();

   //Reset the storage key structure
   free_TPM_KEY(&vtpm_globals.storage_key);
   {
      TPM_KEY key = TPM_KEY_INIT;
      vtpm_globals.storage_key = key;
   }

   //Reset the storage key handle
   TPM_EvictKey(vtpm_globals.storage_key_handle);
   vtpm_globals.storage_key_handle = 0;
egress:
   return status;
}

#if 0
/* For testing disk IO */
void add_fake_vtpms(int num) {
   for(int i = 0; i < num; ++i) {
      uint32_t ind = cpu_to_be32(i);

      uuid_t uuid;
      memset(uuid, 0, sizeof(uuid_t));
      memcpy(uuid, &ind, sizeof(ind));
      int index = vtpm_get_index(uuid);
      index = -index-1;

      vtpm_storage_new_vtpm(uuid, index);
   }
}
#endif
