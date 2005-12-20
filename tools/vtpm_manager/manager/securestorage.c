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
                            CRYPTO_INFO  *asymkey,
                            buffer_t           *sealed_data) {
  TPM_RESULT status = TPM_SUCCESS;
  symkey_t    symkey;
  buffer_t    data_cipher = NULL_BUF,
              symkey_cipher = NULL_BUF;
  
  UINT32 i;
  struct pack_constbuf_t symkey_cipher32, data_cipher32;
  
  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Enveloping[%d]: 0x", buffer_len(inbuf));
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
  goto egress;

 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to envelope encrypt\n.");
  
 egress:
  
  buffer_free ( &data_cipher);
  buffer_free ( &symkey_cipher);
  Crypto_symcrypto_freekey (&symkey);
  
  return status;
}

TPM_RESULT envelope_decrypt(const long         cipher_size,
                            const BYTE         *cipher,
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

  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "envelope decrypting[%ld]: 0x", cipher_size);
  for (i=0; i< cipher_size; i++)
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cipher[i]);
  vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
  
  BSG_UnpackList(cipher, 2,
		 BSG_TPM_SIZE32_DATA, &symkey_cipher32,
		 BSG_TPM_SIZE32_DATA, &data_cipher32);
  
  TPMTRYRETURN( buffer_init_convert (&symkey_cipher, 
				     symkey_cipher32.size, 
				     symkey_cipher32.data) );
  
  TPMTRYRETURN( buffer_init_convert (&data_cipher, 
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
  buffer_t sealed_NVM;
  
  
  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Save_NVMing[%d]: 0x\n", buffer_len(inbuf));

  TPMTRYRETURN( envelope_encrypt(inbuf,
                                 &vtpm_globals->storageKey,
                                 &sealed_NVM) );
				  
  // Mark DMI Table so new save state info will get pushed to disk on return.
  vtpm_globals->DMI_table_dirty = TRUE;
  
  // Write sealed blob off disk from NVMLocation
  // TODO: How to properly return from these. Do we care if we return failure
  //       after writing the file? We can't get the old one back.
  // TODO: Backup old file and try and recover that way.
  fh = open(myDMI->NVMLocation, O_WRONLY | O_CREAT, S_IREAD | S_IWRITE);
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


/* inbuf = null outbuf = sealed blob size, sealed blob.*/
TPM_RESULT VTPM_Handle_Load_NVM(VTPM_DMI_RESOURCE *myDMI, 
				const buffer_t *inbuf, 
				buffer_t *outbuf) {
  
  TPM_RESULT status = TPM_SUCCESS;

  
  UINT32 sealed_NVM_size;
  BYTE *sealed_NVM = NULL;
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
  
  sealed_NVM = (BYTE *) malloc(fh_size);
  sealed_NVM_size = (UINT32) fh_size;
  if (read(fh, sealed_NVM, fh_size) != fh_size) {
    status = TPM_IOERROR;
    goto abort_egress;
  }
  close(fh);
  
  vtpmloginfo(VTPM_LOG_VTPM_DEEP, "Load_NVMing[%ld],\n", fh_size);
  
  Crypto_SHA1Full(sealed_NVM, sealed_NVM_size, (BYTE *) &sealedNVMHash);    
  
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
  
    TPMTRYRETURN( envelope_decrypt(fh_size,
                                 sealed_NVM,
                                 myDMI->TCSContext,
		        	 vtpm_globals->storageKeyHandle,
			         (const TPM_AUTHDATA*)&vtpm_globals->storage_key_usage_auth,
                                 outbuf) );  
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to load NVM\n.");
  
 egress:
  free( sealed_NVM );
  
  return status;
}

TPM_RESULT VTPM_SaveService(void) {
  TPM_RESULT status=TPM_SUCCESS;
  int fh, dmis=-1;
  
  BYTE *flat_global;
  int flat_global_size, bytes_written;
  UINT32 storageKeySize = buffer_len(&vtpm_globals->storageKeyWrap);
  struct pack_buf_t storage_key_pack = {storageKeySize, vtpm_globals->storageKeyWrap.bytes};
  
  struct hashtable_itr *dmi_itr;
  VTPM_DMI_RESOURCE *dmi_res;
  
  UINT32 flat_global_full_size;
  
  // Global Values needing to be saved
  flat_global_full_size = 3*sizeof(TPM_DIGEST) + // Auths
    sizeof(UINT32) +       // storagekeysize
    storageKeySize +       // storage key
    hashtable_count(vtpm_globals->dmi_map) * // num DMIS
    (sizeof(UINT32) + 2*sizeof(TPM_DIGEST)); // Per DMI info
  
  
  flat_global = (BYTE *) malloc( flat_global_full_size);
  
  flat_global_size = BSG_PackList(flat_global, 4,
				  BSG_TPM_AUTHDATA, &vtpm_globals->owner_usage_auth,
				  BSG_TPM_AUTHDATA, &vtpm_globals->srk_usage_auth,
				  BSG_TPM_SECRET,   &vtpm_globals->storage_key_usage_auth,
				  BSG_TPM_SIZE32_DATA, &storage_key_pack);
  
  // Per DMI values to be saved
  if (hashtable_count(vtpm_globals->dmi_map) > 0) {
    
    dmi_itr = hashtable_iterator(vtpm_globals->dmi_map);
    do {
      dmi_res = (VTPM_DMI_RESOURCE *) hashtable_iterator_value(dmi_itr);
      dmis++;

      // No need to save dmi0.
      if (dmi_res->dmi_id == 0) 	
	continue;
      
      
      flat_global_size += BSG_PackList( flat_global + flat_global_size, 3,
					BSG_TYPE_UINT32, &dmi_res->dmi_id,
					BSG_TPM_DIGEST, &dmi_res->NVM_measurement,
					BSG_TPM_DIGEST, &dmi_res->DMI_measurement);
      
    } while (hashtable_iterator_advance(dmi_itr));
  }
  
  //FIXME: Once we have a way to protect a TPM key, we should use it to 
  //       encrypt this blob. BUT, unless there is a way to ensure the key is
  //       not used by other apps, this encryption is useless.
  fh = open(STATE_FILE, O_WRONLY | O_CREAT, S_IREAD | S_IWRITE);
  if (fh == -1) {
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to open %s file for write.\n", STATE_FILE);
    status = TPM_IOERROR;
    goto abort_egress;
  }
  
  if ( (bytes_written = write(fh, flat_global, flat_global_size)) != flat_global_size ) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to save service data. %d/%d bytes written.\n", bytes_written, flat_global_size);
    status = TPM_IOERROR;
    goto abort_egress;
  }
  vtpm_globals->DMI_table_dirty = FALSE; 
  
  goto egress;
  
 abort_egress:
 egress:
  
  free(flat_global);
  close(fh);
  
  vtpmloginfo(VTPM_LOG_VTPM, "Saved VTPM Service state (status = %d, dmis = %d)\n", (int) status, dmis);
  return status;
}

TPM_RESULT VTPM_LoadService(void) {
  
  TPM_RESULT status=TPM_SUCCESS;
  int fh, stat_ret, dmis=0;
  long fh_size = 0, step_size;
  BYTE *flat_global=NULL;
  struct pack_buf_t storage_key_pack;
  UINT32 *dmi_id_key;
  
  VTPM_DMI_RESOURCE *dmi_res;
  struct stat file_stat;
  
  fh = open(STATE_FILE, O_RDONLY );
  stat_ret = fstat(fh, &file_stat);
  if (stat_ret == 0) 
    fh_size = file_stat.st_size;
  else {
    status = TPM_IOERROR;
    goto abort_egress;
  }
  
  flat_global = (BYTE *) malloc(fh_size);
  
  if ((long) read(fh, flat_global, fh_size) != fh_size ) {
    status = TPM_IOERROR;
    goto abort_egress;
  }
  
  // Global Values needing to be saved
  step_size = BSG_UnpackList( flat_global, 4,
			      BSG_TPM_AUTHDATA, &vtpm_globals->owner_usage_auth,
			      BSG_TPM_AUTHDATA, &vtpm_globals->srk_usage_auth,
			      BSG_TPM_SECRET,   &vtpm_globals->storage_key_usage_auth,
			      BSG_TPM_SIZE32_DATA, &storage_key_pack);
  
  TPMTRYRETURN(buffer_init(&vtpm_globals->storageKeyWrap, 0, 0) );
  TPMTRYRETURN(buffer_append_raw(&vtpm_globals->storageKeyWrap, storage_key_pack.size, storage_key_pack.data) );
  
  // Per DMI values to be saved
  while ( step_size < fh_size ){
    if (fh_size - step_size < (long) (sizeof(UINT32) + 2*sizeof(TPM_DIGEST))) {
      vtpmlogerror(VTPM_LOG_VTPM, "Encountered %ld extra bytes at end of manager state.\n", fh_size-step_size);
      step_size = fh_size;
    } else {
      dmi_res = (VTPM_DMI_RESOURCE *) malloc(sizeof(VTPM_DMI_RESOURCE));
      dmis++;
      
      dmi_res->connected = FALSE;
      
      step_size += BSG_UnpackList(flat_global + step_size, 3,
				  BSG_TYPE_UINT32, &dmi_res->dmi_id, 
				  BSG_TPM_DIGEST, &dmi_res->NVM_measurement,
				  BSG_TPM_DIGEST, &dmi_res->DMI_measurement);
      
      // install into map
      dmi_id_key = (UINT32 *) malloc (sizeof(UINT32));
      *dmi_id_key = dmi_res->dmi_id;
      if (!hashtable_insert(vtpm_globals->dmi_map, dmi_id_key, dmi_res)) {
	status = TPM_FAIL;
	goto abort_egress;
      }
      
    }
    
  }
  
  vtpmloginfo(VTPM_LOG_VTPM, "Loaded saved state (dmis = %d).\n", dmis);
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to load service data with error = %s\n", tpm_get_error_name(status));
 egress:
  
  free(flat_global);
  close(fh);
  
  return status;
}
