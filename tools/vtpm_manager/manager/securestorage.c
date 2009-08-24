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
// securestorage.c
// 
//  Functions regarding securely storing DMI secrets.
//
// ==================================================================

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "tcg.h"
#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "vtsp.h"
#include "bsg.h"
#include "crypto.h"
#include "hashtable.h"
#include "hashtable_itr.h"
#include "buffer.h"
#include "log.h"

TPM_RESULT envelope_encrypt(const buffer_t     *inbuf,
                            CRYPTO_INFO        *asymkey,
                            buffer_t           *sealed_data) {
  TPM_RESULT status = TPM_SUCCESS;
  symkey_t    symkey;
  buffer_t    data_cipher = NULL_BUF,
              symkey_cipher = NULL_BUF;
  
  UINT32 i;
  struct pack_constbuf_t symkey_cipher32, data_cipher32;
  
  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Enveloping Input[%d]: 0x", buffer_len(inbuf));
  for (i=0; i< buffer_len(inbuf); i++)
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", inbuf->bytes[i]);
  vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
  
  // Generate a sym key and encrypt state with it
  TPMTRY(TPM_ENCRYPT_ERROR, Crypto_symcrypto_genkey (&symkey) );
  TPMTRY(TPM_ENCRYPT_ERROR, Crypto_symcrypto_encrypt (&symkey, inbuf, &data_cipher) );
  
  // Encrypt symmetric key
  TPMTRYRETURN( VTSP_Bind(    asymkey, 
			      &symkey.key, 
			      &symkey_cipher) );
  
  // Create output blob: symkey_size + symkey_cipher + state_cipher_size + state_cipher
  
  symkey_cipher32.size = buffer_len(&symkey_cipher);
  symkey_cipher32.data = symkey_cipher.bytes;
  
  data_cipher32.size = buffer_len(&data_cipher);
  data_cipher32.data = data_cipher.bytes;
  
  TPMTRYRETURN( buffer_init(sealed_data, 2 * sizeof(UINT32) + symkey_cipher32.size + data_cipher32.size, NULL));
  
  BSG_PackList(sealed_data->bytes, 2,
	       BSG_TPM_SIZE32_DATA, &symkey_cipher32,
	       BSG_TPM_SIZE32_DATA, &data_cipher32);

  vtpmloginfo(VTPM_LOG_VTPM, "Saved %d bytes of E(symkey) + %d bytes of E(data)\n", buffer_len(&symkey_cipher), buffer_len(&data_cipher));

  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Enveloping Output[%d]: 0x", buffer_len(sealed_data));
  for (i=0; i< buffer_len(sealed_data); i++)
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", sealed_data->bytes[i]);
  vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");

  goto egress;

 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to envelope encrypt\n.");
  
 egress:
  
  buffer_free ( &data_cipher);
  buffer_free ( &symkey_cipher);
  Crypto_symcrypto_freekey (&symkey);
  
  return status;
}

TPM_RESULT envelope_decrypt(const buffer_t     *cipher,
                            TCS_CONTEXT_HANDLE TCSContext,
			    TPM_HANDLE         keyHandle,
			    const TPM_AUTHDATA *key_usage_auth,
                            buffer_t           *unsealed_data) {

  TPM_RESULT status = TPM_SUCCESS;
  symkey_t    symkey;
  buffer_t    data_cipher = NULL_BUF, 
              symkey_clear = NULL_BUF, 
              symkey_cipher = NULL_BUF;
  struct pack_buf_t symkey_cipher32, data_cipher32;
  int i;

  memset(&symkey, 0, sizeof(symkey_t));

  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Envelope Decrypt Input[%d]: 0x", buffer_len(cipher) );
  for (i=0; i< buffer_len(cipher); i++)
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cipher->bytes[i]);
  vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
  
  BSG_UnpackList(cipher->bytes, 2,
		 BSG_TPM_SIZE32_DATA, &symkey_cipher32,
		 BSG_TPM_SIZE32_DATA, &data_cipher32);
  
  TPMTRYRETURN( buffer_init_alias_convert (&symkey_cipher, 
				           symkey_cipher32.size, 
				           symkey_cipher32.data) );
  
  TPMTRYRETURN( buffer_init_alias_convert (&data_cipher, 
				           data_cipher32.size, 
				           data_cipher32.data) );

  // Decrypt Symmetric Key
  TPMTRYRETURN( VTSP_Unbind(  TCSContext,
			      keyHandle,
			      &symkey_cipher,
			      key_usage_auth,
			      &symkey_clear,
			      &(vtpm_globals->keyAuth) ) );
  
  // create symmetric key using saved bits
  Crypto_symcrypto_initkey (&symkey, &symkey_clear);
  
  // Decrypt State
  TPMTRY(TPM_DECRYPT_ERROR, Crypto_symcrypto_decrypt (&symkey, &data_cipher, unsealed_data) );

  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Envelope Decrypte Output[%d]: 0x", buffer_len(unsealed_data));
  for (i=0; i< buffer_len(unsealed_data); i++)
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", unsealed_data->bytes[i]);
  vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
  
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to envelope decrypt data\n.");
  
 egress:
  buffer_free ( &data_cipher);
  buffer_free ( &symkey_clear);
  buffer_free ( &symkey_cipher);
  Crypto_symcrypto_freekey (&symkey);
  
  return status;
}

TPM_RESULT VTPM_Handle_Save_NVM(VTPM_DMI_RESOURCE *myDMI, 
				const buffer_t *inbuf, 
				buffer_t *outbuf) {
  
  TPM_RESULT status = TPM_SUCCESS;
  int fh;
  long bytes_written;
  buffer_t sealed_NVM = NULL_BUF;
  
  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Saving %d bytes of NVM.\n", buffer_len(inbuf));

  TPMTRYRETURN( envelope_encrypt(inbuf,
                                 &vtpm_globals->storageKey,
                                 &sealed_NVM) );
				  
  // Write sealed blob off disk from NVMLocation
  // TODO: How to properly return from these. Do we care if we return failure
  //       after writing the file? We can't get the old one back.
  // TODO: Backup old file and try and recover that way.
  fh = open(myDMI->NVMLocation, O_WRONLY | O_CREAT | O_TRUNC, S_IREAD | S_IWRITE);
  if ( (bytes_written = write(fh, sealed_NVM.bytes, buffer_len(&sealed_NVM) ) != (long) buffer_len(&sealed_NVM))) {
    vtpmlogerror(VTPM_LOG_VTPM, "We just overwrote a DMI_NVM and failed to finish. %ld/%ld bytes.\n", bytes_written, (long)buffer_len(&sealed_NVM));
    status = TPM_IOERROR;
    goto abort_egress;
  }
  close(fh);
  
  Crypto_SHA1Full (sealed_NVM.bytes, buffer_len(&sealed_NVM), (BYTE *) &myDMI->NVM_measurement);   
  
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to save NVM\n.");
  
 egress:
  buffer_free(&sealed_NVM);
  return status;
}


/* Expected Params: inbuf = null, outbuf = sealed blob size, sealed blob.*/
TPM_RESULT VTPM_Handle_Load_NVM(VTPM_DMI_RESOURCE *myDMI, 
				const buffer_t    *inbuf, 
				buffer_t          *outbuf) {
  
  TPM_RESULT status = TPM_SUCCESS;

  buffer_t sealed_NVM = NULL_BUF;
  long fh_size;
  int fh, stat_ret, i;
  struct stat file_stat;
  TPM_DIGEST sealedNVMHash;
   
  if (myDMI->NVMLocation == NULL) {
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to load NVM because the file name NULL.\n");
    status = TPM_AUTHFAIL;
    goto abort_egress;
  }
  
  //Read sealed blob off disk from NVMLocation
  fh = open(myDMI->NVMLocation, O_RDONLY);
  stat_ret = fstat(fh, &file_stat);
  if (stat_ret == 0) 
    fh_size = file_stat.st_size;
  else {
    status = TPM_IOERROR;
    goto abort_egress;
  }
  
  TPMTRYRETURN( buffer_init( &sealed_NVM, fh_size, NULL) );
  if (read(fh, sealed_NVM.bytes, buffer_len(&sealed_NVM)) != fh_size) {
    status = TPM_IOERROR;
    goto abort_egress;
  }
  close(fh);
  
  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Load_NVMing[%d],\n", buffer_len(&sealed_NVM));
  
  Crypto_SHA1Full(sealed_NVM.bytes, buffer_len(&sealed_NVM), (BYTE *) &sealedNVMHash);    
  
  // Verify measurement of sealed blob.
  if (memcmp(&sealedNVMHash, &myDMI->NVM_measurement, sizeof(TPM_DIGEST)) ) {
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM LoadNVM NVM measurement check failed.\n");
    vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Correct hash: ");
    for (i=0; i< sizeof(TPM_DIGEST); i++)
      vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", ((BYTE*)&myDMI->NVM_measurement)[i]);
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");

    vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Measured hash: ");
    for (i=0; i< sizeof(TPM_DIGEST); i++)
      vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", ((BYTE*)&sealedNVMHash)[i]);
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
    
    status = TPM_AUTHFAIL;
    goto abort_egress;
  }
  
  TPMTRYRETURN( envelope_decrypt(&sealed_NVM,
                                 myDMI->TCSContext,
		        	 vtpm_globals->storageKeyHandle,
			         (const TPM_AUTHDATA*)&vtpm_globals->storage_key_usage_auth,
                                 outbuf) );  
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to load NVM\n.");
  
 egress:
  buffer_free( &sealed_NVM );
  
  return status;
}


TPM_RESULT VTPM_SaveManagerData(void) {
  TPM_RESULT status=TPM_SUCCESS;
  int fh, dmis=-1;

  BYTE *flat_boot_key=NULL, *flat_dmis=NULL, *flat_enc=NULL;
  buffer_t clear_flat_global=NULL_BUF, enc_flat_global=NULL_BUF;
  UINT32 storageKeySize = buffer_len(&vtpm_globals->storageKeyWrap);
  UINT32 bootKeySize = buffer_len(&vtpm_globals->bootKeyWrap);
  struct pack_buf_t storage_key_pack = {storageKeySize, vtpm_globals->storageKeyWrap.bytes};
  struct pack_buf_t boot_key_pack = {bootKeySize, vtpm_globals->bootKeyWrap.bytes};
  BYTE vtpm_manager_gen = VTPM_MANAGER_GEN;

  struct hashtable_itr *dmi_itr;
  VTPM_DMI_RESOURCE *dmi_res;

  UINT32 boot_key_size = 0, flat_dmis_size = 0;

  // Initially fill these with buffer sizes for each data type. Later fill
  // in actual size, once flattened.
  boot_key_size =  sizeof(UINT32) +       // bootkeysize
                   bootKeySize;           // boot key

  TPMTRYRETURN(buffer_init(&clear_flat_global,sizeof(BYTE) + // manager version
                                              3*sizeof(TPM_DIGEST) + // Auths
                                              sizeof(UINT32) +// storagekeysize
                                              storageKeySize, NULL) ); // storage key


  flat_boot_key = (BYTE *) malloc( boot_key_size );
  flat_enc = (BYTE *) malloc( sizeof(UINT32) );

  boot_key_size = BSG_PackList(flat_boot_key, 1,
                               BSG_TPM_SIZE32_DATA, &boot_key_pack);

  BSG_PackList(clear_flat_global.bytes, 4,
                BSG_TYPE_BYTE,    &vtpm_manager_gen,
                BSG_TPM_AUTHDATA, &vtpm_globals->owner_usage_auth,
                BSG_TPM_SECRET,   &vtpm_globals->storage_key_usage_auth,
                BSG_TPM_SIZE32_DATA, &storage_key_pack);

  TPMTRYRETURN(envelope_encrypt(&clear_flat_global,
                                &vtpm_globals->bootKey,
                                &enc_flat_global) );

  BSG_PackConst(buffer_len(&enc_flat_global), 4, flat_enc);

  // Per DMI values to be saved (if any exit)
  if (hashtable_count(vtpm_globals->dmi_map) > 1) {

    flat_dmis = (BYTE *) malloc( 
                     (hashtable_count(vtpm_globals->dmi_map) - 1) * // num DMIS (-1 for Dom0)
                     (sizeof(UINT32) +sizeof(BYTE) + 2*sizeof(TPM_DIGEST)) ); // Per DMI info

    dmi_itr = hashtable_iterator(vtpm_globals->dmi_map);
    do {
      dmi_res = (VTPM_DMI_RESOURCE *) hashtable_iterator_value(dmi_itr);
      dmis++;

      // No need to save dmi0.
      if (dmi_res->dmi_id == 0)
        continue;


      flat_dmis_size += BSG_PackList( flat_dmis + flat_dmis_size, 4,
                                        BSG_TYPE_UINT32, &dmi_res->dmi_id,
                                        BSG_TYPE_BYTE, &dmi_res->dmi_type,
                                        BSG_TPM_DIGEST, &dmi_res->NVM_measurement,
                                        BSG_TPM_DIGEST, &dmi_res->DMI_measurement);

    } while (hashtable_iterator_advance(dmi_itr));
  }

  fh = open(STATE_FILE, O_WRONLY | O_CREAT, S_IREAD | S_IWRITE);
  if (fh == -1) {
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to open %s file for write.\n", STATE_FILE);
    status = TPM_IOERROR;
    goto abort_egress;
  }

  if ( ( write(fh, flat_boot_key, boot_key_size) != boot_key_size ) ||
       ( write(fh, flat_enc, sizeof(UINT32)) != sizeof(UINT32) ) ||
       ( write(fh, enc_flat_global.bytes, buffer_len(&enc_flat_global)) != buffer_len(&enc_flat_global) ) ||
       ( write(fh, flat_dmis, flat_dmis_size) != flat_dmis_size ) ) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to completely write service data.\n");
    status = TPM_IOERROR;
    goto abort_egress;
 }

  goto egress;

 abort_egress:
 egress:

  free(flat_boot_key);
  free(flat_enc);
  buffer_free(&enc_flat_global);
  free(flat_dmis);
  close(fh);

  vtpmloginfo(VTPM_LOG_VTPM, "Saved VTPM Manager state (status = %d, dmis = %d)\n", (int) status, dmis);
  return status;
}

TPM_RESULT VTPM_LoadManagerData(void) {

  TPM_RESULT status=TPM_SUCCESS;
  int fh, stat_ret, dmis=0;
  long fh_size = 0, step_size;
  BYTE *flat_table=NULL;
  buffer_t  unsealed_data, enc_table_abuf;
  struct pack_buf_t storage_key_pack, boot_key_pack;
  UINT32 *dmi_id_key, enc_size;
  BYTE vtpm_manager_gen;

  VTPM_DMI_RESOURCE *dmi_res;
  UINT32 dmi_id;
  BYTE dmi_type;
  struct stat file_stat;

  TPM_HANDLE boot_key_handle;
  TPM_AUTHDATA boot_usage_auth;
  memset(&boot_usage_auth, 0, sizeof(TPM_AUTHDATA));

  fh = open(STATE_FILE, O_RDONLY );
  stat_ret = fstat(fh, &file_stat);
  if (stat_ret == 0)
    fh_size = file_stat.st_size;
  else {
    status = TPM_IOERROR;
    goto abort_egress;
  }

  flat_table = (BYTE *) malloc(fh_size);

  if ((long) read(fh, flat_table, fh_size) != fh_size ) {
    status = TPM_IOERROR;
    goto abort_egress;
  }

  // Read Boot Key
  step_size = BSG_UnpackList( flat_table, 2,
                              BSG_TPM_SIZE32_DATA, &boot_key_pack,
                              BSG_TYPE_UINT32, &enc_size);

  TPMTRYRETURN(buffer_init(&vtpm_globals->bootKeyWrap, 0, 0) );
  TPMTRYRETURN(buffer_init_alias_convert(&enc_table_abuf, enc_size, flat_table + step_size) );
  TPMTRYRETURN(buffer_append_raw(&vtpm_globals->bootKeyWrap, boot_key_pack.size, boot_key_pack.data) );

  //Load Boot Key
  TPMTRYRETURN( VTSP_LoadKey( vtpm_globals->manager_tcs_handle,
                              TPM_SRK_KEYHANDLE,
                              &vtpm_globals->bootKeyWrap,
                              &SRK_AUTH,
                              &boot_key_handle,
                              &vtpm_globals->keyAuth,
                              &vtpm_globals->bootKey,
                              FALSE) );

  TPMTRYRETURN( envelope_decrypt(&enc_table_abuf,
                                 vtpm_globals->manager_tcs_handle,
                                 boot_key_handle,
                                 (const TPM_AUTHDATA*) &boot_usage_auth,
                                 &unsealed_data) );
  step_size += enc_size;

  if (*unsealed_data.bytes != VTPM_MANAGER_GEN) {
      // Once there is more than one gen, this will include some compatability stuff
      vtpmlogerror(VTPM_LOG_VTPM, "Warning: Manager Data file is gen %d, which this manager is gen %d.\n", vtpm_manager_gen, VTPM_MANAGER_GEN);
  }

  // Global Values needing to be saved
  BSG_UnpackList( unsealed_data.bytes, 4,
                  BSG_TYPE_BYTE,    &vtpm_manager_gen, 
                  BSG_TPM_AUTHDATA, &vtpm_globals->owner_usage_auth,
                  BSG_TPM_SECRET,   &vtpm_globals->storage_key_usage_auth,
                  BSG_TPM_SIZE32_DATA, &storage_key_pack);

  TPMTRYRETURN(buffer_init(&vtpm_globals->storageKeyWrap, 0, 0) );
  TPMTRYRETURN(buffer_append_raw(&vtpm_globals->storageKeyWrap, storage_key_pack.size, storage_key_pack.data) );

  // Per DMI values to be saved
  while ( step_size < fh_size ){
    if (fh_size - step_size < (long) (sizeof(UINT32) + sizeof(BYTE) + 2*sizeof(TPM_DIGEST))) {
      vtpmlogerror(VTPM_LOG_VTPM, "Encountered %ld extra bytes at end of manager state.\n", fh_size-step_size);
      step_size = fh_size;
    } else {
      step_size += BSG_UnpackList(flat_table + step_size, 2,
                                 BSG_TYPE_UINT32, &dmi_id,
                                 BSG_TYPE_BYTE, &dmi_type);

      //TODO: Try and gracefully recover from problems.
      TPMTRYRETURN(init_dmi(dmi_id, dmi_type, &dmi_res) );
      dmis++;

      step_size += BSG_UnpackList(flat_table + step_size, 2,
                                 BSG_TPM_DIGEST, &dmi_res->NVM_measurement,
                                 BSG_TPM_DIGEST, &dmi_res->DMI_measurement);
    }

  }

  vtpmloginfo(VTPM_LOG_VTPM, "Loaded saved state (dmis = %d).\n", dmis);
  goto egress;

 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to load service data with error = %s\n", tpm_get_error_name(status));
 egress:

  free(flat_table);
  close(fh);

  // TODO: Could be nice and evict BootKey. (Need to add EvictKey to VTSP.

  return status;
}

