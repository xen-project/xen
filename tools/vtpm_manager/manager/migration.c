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
//   dmictl.c
// 
//     Functions for creating and destroying DMIs
//
// ==================================================================

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "vtpmpriv.h"
#include "bsg.h"
#include "buffer.h"
#include "log.h"
#include "hashtable.h"

TPM_RESULT VTPM_Handle_Migrate_In( const buffer_t *param_buf,
                                   buffer_t *result_buf) {

  TPM_RESULT status=TPM_FAIL;
  VTPM_DMI_RESOURCE *mig_dmi=NULL;
  UINT32 dmi_id;
  buffer_t dmi_state_abuf = NULL_BUF, enc_dmi_abuf = NULL_BUF, clear_dmi_blob = NULL_BUF;

  if (param_buf == NULL) {
    vtpmlogerror(VTPM_LOG_VTPM, "Migration Out Failed due to bad parameter.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  struct pack_buf_t enc_dmi_state_pack;

  BSG_UnpackList(param_buf->bytes, 2, 
                 BSG_TYPE_UINT32, &dmi_id,
                 BSG_TPM_SIZE32_DATA, &enc_dmi_state_pack) ;

  vtpmloginfo(VTPM_LOG_VTPM, "Migrating VTPM in dmi %d.\n", dmi_id);

  mig_dmi = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi_id);
  if (mig_dmi) {
    vtpmlogerror(VTPM_LOG_VTPM, "Incoming VTPM claims unavailable id: %d.\n", dmi_id);
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }    

  /** UnBind Blob **/
  TPMTRYRETURN( buffer_init_alias_convert( &enc_dmi_abuf, 
                                           enc_dmi_state_pack.size, 
                                           enc_dmi_state_pack.data) );

  TPMTRYRETURN( envelope_decrypt( &enc_dmi_abuf,
                                   vtpm_globals->manager_tcs_handle,
                                   vtpm_globals->storageKeyHandle,
                                   (const TPM_AUTHDATA*)&vtpm_globals->storage_key_usage_auth,
                                   &clear_dmi_blob) );

  // Create new dmi
  TPMTRYRETURN( init_dmi(dmi_id, VTPM_TYPE_MIGRATABLE, &mig_dmi ) ); 

  /** Open Blob **/
  struct pack_buf_t dmi_state_pack;

  BSG_UnpackList(clear_dmi_blob.bytes, 2, 
                 BSG_TPM_DIGEST, &mig_dmi->DMI_measurement,
                 BSG_TPM_SIZE32_DATA, &dmi_state_pack);

  TPMTRYRETURN( buffer_init_alias_convert(&dmi_state_abuf, 
                                          dmi_state_pack.size, 
                                          dmi_state_pack.data) ); 

  TPMTRYRETURN( VTPM_Handle_Save_NVM(mig_dmi, &dmi_state_abuf, NULL ) );

  status=TPM_SUCCESS;
  goto egress;

 abort_egress:
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM Migration IN of instance %d failed because of %s.\n", dmi_id, tpm_get_error_name(status) );

 egress:
  buffer_free(&clear_dmi_blob);
  buffer_free(&dmi_state_abuf);
 
  return status;
}

TPM_RESULT VTPM_Handle_Migrate_Out( const buffer_t *param_buf,
                                    buffer_t *result_buf) {

  TPM_RESULT status=TPM_FAIL;
  VTPM_DMI_RESOURCE *mig_dmi;
  UINT32 dmi_id;
  VTPM_MIGKEY_LIST *last_mig, *mig_key;
  buffer_t dmi_state=NULL_BUF, clear_dmi_blob=NULL_BUF;

  if (param_buf == NULL) {
    vtpmlogerror(VTPM_LOG_VTPM, "Migration Out Failed due to bad parameter.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  struct pack_buf_t name_pack;

  BSG_UnpackList( param_buf->bytes, 2,
                  BSG_TYPE_UINT32, &dmi_id,
                  BSG_TPM_SIZE32_DATA, &name_pack);

  vtpmloginfo(VTPM_LOG_VTPM, "Migrating out dmi %d.\n", dmi_id);

  mig_dmi = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi_id);
  if (mig_dmi == NULL) {
    vtpmlogerror(VTPM_LOG_VTPM, "Non-existent VTPM instance (%d) in migration.\n", dmi_id );
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  if (mig_dmi->dmi_type != VTPM_TYPE_MIGRATABLE) {
    vtpmlogerror(VTPM_LOG_VTPM, "Bad VTPM type (%d) in migration of instance (%d).\n", mig_dmi->dmi_type, dmi_id );
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  /** Find migration key for dest **/
  last_mig = NULL;
  mig_key = vtpm_globals->mig_keys;
  while (mig_key != NULL) {
    if (mig_key->name_size == name_pack.size)
      if (memcmp(mig_key->name, name_pack.data, name_pack.size) == 0) {
        break;
      }
    
    last_mig = mig_key;
    mig_key = mig_key->next;
  }
     
  if (!mig_key) {
    vtpmlogerror(VTPM_LOG_VTPM, "Unknown Migration target host.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  /** Mark vtpm as migrated **/
  mig_dmi->dmi_type = VTPM_TYPE_MIGRATED;

  /** Build Blob **/
  TPMTRYRETURN( VTPM_Handle_Load_NVM(mig_dmi, NULL, &dmi_state) );

  TPMTRYRETURN( buffer_init(&clear_dmi_blob, sizeof(TPM_DIGEST) + sizeof(UINT32) + buffer_len(&dmi_state), NULL ) ); 

  struct pack_constbuf_t dmi_state_pack;

  dmi_state_pack.size = buffer_len(&dmi_state);
  dmi_state_pack.data = dmi_state.bytes;

  BSG_PackList(clear_dmi_blob.bytes, 2, 
               BSG_TPM_DIGEST, &mig_dmi->DMI_measurement,
               BSG_TPM_SIZE32_DATA, &dmi_state_pack);

  /** Bind Blob **/
  TPMTRYRETURN( envelope_encrypt( &clear_dmi_blob,
                                  &mig_key->key,
                                  result_buf) );

  if (last_mig)
    last_mig->next = mig_key->next;
  else 
    vtpm_globals->mig_keys = mig_key->next;
  
  free(mig_key->name);
  free(mig_key);

  status=TPM_SUCCESS;
  goto egress;

 abort_egress:
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM Migration OUT of instance %d failed because of %s. Migratoin recovery may be needed.\n", dmi_id, tpm_get_error_name(status) );

    //TODO: Create and implement a policy for what happens to mig_key on failed migrations.

 egress:

  buffer_free(&clear_dmi_blob);
  buffer_free(&dmi_state);

  return status;
}


TPM_RESULT VTPM_Handle_Get_Migration_key( const buffer_t *param_buf,
                                          buffer_t *result_buf) {

  TPM_RESULT status=TPM_FAIL;

  vtpmloginfo(VTPM_LOG_VTPM, "Getting Migration Public Key.\n");

  struct pack_buf_t pubkey_exp_pack, pubkey_mod_pack;
  TPM_KEY mig_key;

  // Unpack/return key structure
  BSG_Unpack(BSG_TPM_KEY, vtpm_globals->storageKeyWrap.bytes , &mig_key);
  TPM_RSA_KEY_PARMS rsaKeyParms;

  BSG_Unpack(BSG_TPM_RSA_KEY_PARMS,
               mig_key.algorithmParms.parms,
               &rsaKeyParms);

  pubkey_exp_pack.size = rsaKeyParms.exponentSize;
  pubkey_exp_pack.data = rsaKeyParms.exponent;
  pubkey_mod_pack.size = mig_key.pubKey.keyLength;
  pubkey_mod_pack.data = mig_key.pubKey.key;

  TPMTRYRETURN( buffer_init( result_buf, 2*sizeof(UINT32) + 
                                         pubkey_exp_pack.size + 
                                         pubkey_mod_pack.size, NULL ) );

  BSG_PackList( result_buf->bytes, 2,
                  BSG_TPM_SIZE32_DATA, &pubkey_exp_pack,
                  BSG_TPM_SIZE32_DATA, &pubkey_mod_pack);


  status=TPM_SUCCESS;
  goto egress;

 abort_egress:
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM Get Migration Key failed because of %s.\n", tpm_get_error_name(status) );
 egress:

  return status;
}

TPM_RESULT VTPM_Handle_Load_Migration_key( const buffer_t *param_buf,
                                           buffer_t *result_buf) {

  TPM_RESULT status=TPM_FAIL;
  VTPM_MIGKEY_LIST *mig_key;

  vtpmloginfo(VTPM_LOG_VTPM, "Loading Migration Public Key.\n");

  //FIXME: Review all uses of unpacking pack_buf_t and ensure free.
  //FIXME: Review all declarations/initializations of buffer_t that could have a goto that skips them and then tries to free them

  struct pack_buf_t name_pack, pubkey_exp_pack, pubkey_mod_pack;

  //FIXME: scan list and verify name is not already in the list

  BSG_UnpackList( param_buf->bytes, 3,
                  BSG_TPM_SIZE32_DATA, &name_pack,
                  BSG_TPM_SIZE32_DATA, &pubkey_exp_pack,
                  BSG_TPM_SIZE32_DATA, &pubkey_mod_pack);

  //TODO: Maintain a persistent list for pub_keys.
  //TODO: Verify pub_key is trusted

  mig_key = (VTPM_MIGKEY_LIST *) malloc(sizeof(VTPM_MIGKEY_LIST));
  memset(mig_key, 0, sizeof(VTPM_MIGKEY_LIST) );
  mig_key->name_size = name_pack.size;
  mig_key->name = name_pack.data;

  mig_key->key.encScheme = CRYPTO_ES_RSAESOAEP_SHA1_MGF1;
  Crypto_RSABuildCryptoInfoPublic( pubkey_exp_pack.size,
                                   pubkey_exp_pack.data,
                                   pubkey_mod_pack.size,
                                   pubkey_mod_pack.data,
                                   &mig_key->key);


  mig_key->next = vtpm_globals->mig_keys;
  vtpm_globals->mig_keys = mig_key;

  // free(name_pack.data); Do not free. data is now part of mig_key.
  free(pubkey_exp_pack.data);
  free(pubkey_mod_pack.data);

  return TPM_SUCCESS;
}
