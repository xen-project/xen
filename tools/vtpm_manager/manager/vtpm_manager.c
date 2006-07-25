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
// vtpm_manager.c
// 
//  This file will house the main logic of the VTPM Manager
//
// ==================================================================

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "vtsp.h"
#include "bsg.h"
#include "hashtable.h"
#include "hashtable_itr.h"

#include "log.h"
#include "buffer.h"

VTPM_GLOBALS *vtpm_globals=NULL;

// --------------------------- Well Known Auths --------------------------
const TPM_AUTHDATA SRK_AUTH = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef WELL_KNOWN_OWNER_AUTH
static BYTE FIXED_OWNER_AUTH[20] =  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
#endif


// -------------------------- Hash table functions --------------------

static unsigned int hashfunc32(void *ky) {
  return (* (UINT32 *) ky);
}

static int equals32(void *k1, void *k2) {
  return (*(UINT32 *) k1 == *(UINT32 *) k2);
}

// --------------------------- Functions ------------------------------

TPM_RESULT VTPM_Create_Manager(){
  
  TPM_RESULT status = TPM_SUCCESS;
  
  // Generate Auth for Owner
#ifdef WELL_KNOWN_OWNER_AUTH 
  memcpy(vtpm_globals->owner_usage_auth, FIXED_OWNER_AUTH, sizeof(TPM_AUTHDATA));
#else    
  Crypto_GetRandom(vtpm_globals->owner_usage_auth, sizeof(TPM_AUTHDATA) );
#endif

  // Take Owership of TPM
  CRYPTO_INFO ek_cryptoInfo;
  
  status = VTSP_ReadPubek(vtpm_globals->manager_tcs_handle, &ek_cryptoInfo);
  
  // If we can read PubEK then there is no owner and we should take it.
  // We use the abilty to read the pubEK to flag that the TPM is owned.
  // FIXME: Change to just trying to take ownership and react to the status
  if (status == TPM_SUCCESS) { 
    TPMTRYRETURN(VTSP_TakeOwnership(vtpm_globals->manager_tcs_handle,
				    (const TPM_AUTHDATA*)&vtpm_globals->owner_usage_auth, 
				    &SRK_AUTH,
				    &ek_cryptoInfo,
				    &vtpm_globals->keyAuth)); 
  
    TPMTRYRETURN(VTSP_DisablePubekRead(vtpm_globals->manager_tcs_handle,
                                       (const TPM_AUTHDATA*)&vtpm_globals->owner_usage_auth,  
                                       &vtpm_globals->keyAuth));     
  } else {
    vtpmloginfo(VTPM_LOG_VTPM, "Failed to readEK meaning TPM has an owner. Creating Keys off existing SRK.\n");
  }
  
  // Generate storage key's auth
  Crypto_GetRandom(  &vtpm_globals->storage_key_usage_auth, 
		     sizeof(TPM_AUTHDATA) );
  
  TCS_AUTH osap;
  TPM_AUTHDATA sharedsecret;
  
  TPMTRYRETURN( VTSP_OSAP(vtpm_globals->manager_tcs_handle,
			  TPM_ET_KEYHANDLE,
			  TPM_SRK_KEYHANDLE, 
			  &SRK_AUTH,
			  &sharedsecret, 
			  &osap) ); 

  osap.fContinueAuthSession = FALSE;
 
 
  TPMTRYRETURN( VTSP_CreateWrapKey( vtpm_globals->manager_tcs_handle,
				    TPM_KEY_BIND,
				    (const TPM_AUTHDATA*)&vtpm_globals->storage_key_usage_auth,
				    TPM_SRK_KEYHANDLE, 
				    (const TPM_AUTHDATA*)&sharedsecret,
				    &vtpm_globals->storageKeyWrap,
				    &osap) );
  
  // Generate boot key's auth
  TPM_AUTHDATA bootKeyWrapAuth;
  memset(&bootKeyWrapAuth, 0, sizeof(bootKeyWrapAuth));
  
  TPMTRYRETURN( VTSP_OSAP(vtpm_globals->manager_tcs_handle,
			  TPM_ET_KEYHANDLE,
			  TPM_SRK_KEYHANDLE, 
			  &SRK_AUTH,
			  &sharedsecret, 
			  &osap) ); 

  osap.fContinueAuthSession = FALSE;
 
  // FIXME: This key protects the global secrets on disk. It should use TPM
  //        PCR bindings to limit its use to legit configurations.
  //        Current binds are open, implying a Trusted VM contains this code.
  //        If this VM is not Trusted, use measurement and PCR bindings.
  TPMTRYRETURN( VTSP_CreateWrapKey( vtpm_globals->manager_tcs_handle,
				    TPM_KEY_BIND,
				    (const TPM_AUTHDATA*)&bootKeyWrapAuth,
				    TPM_SRK_KEYHANDLE, 
				    (const TPM_AUTHDATA*)&sharedsecret,
				    &vtpm_globals->bootKeyWrap,
				    &osap) );

  // Populate CRYPTO_INFO vtpm_globals->bootKey. This does not load it into the TPM
  TPMTRYRETURN( VTSP_LoadKey( vtpm_globals->manager_tcs_handle,
                              TPM_SRK_KEYHANDLE,
                              &vtpm_globals->bootKeyWrap,
                              NULL,
                              NULL,
                              NULL,
                              &vtpm_globals->bootKey,
                              TRUE ) );

  TPMTRYRETURN( VTSP_SaveState(vtpm_globals->manager_tcs_handle) );
  goto egress;
  
 abort_egress:
  exit(1);
  
 egress:
  vtpmloginfo(VTPM_LOG_VTPM, "Finished initialized new VTPM manager (Status = %d).\n", status);
  return status;
  
}

///////////////////////////////////////////////////////////////////////////////
TPM_RESULT VTPM_Init_Manager() {
  TPM_RESULT status = TPM_FAIL, serviceStatus;   
  BYTE *randomsead;
  UINT32 randomsize=256;

  if ((vtpm_globals = (VTPM_GLOBALS *) malloc(sizeof(VTPM_GLOBALS))) == NULL){
    status = TPM_FAIL;
    goto abort_egress;
  }
  memset(vtpm_globals, 0, sizeof(VTPM_GLOBALS));

  vtpm_globals->connected_dmis = 0;

  if ((vtpm_globals->dmi_map = create_hashtable(10, hashfunc32, equals32)) == NULL){
    status = TPM_FAIL;
    goto abort_egress;
  }
  
  // Create new TCS Object
  vtpm_globals->manager_tcs_handle = 0;
 
  TPMTRYRETURN(TCS_create());
  
  // Create TCS Context for service
  TPMTRYRETURN( TCS_OpenContext(&vtpm_globals->manager_tcs_handle ) );

  TPMTRYRETURN( TCSP_GetRandom(vtpm_globals->manager_tcs_handle, 
			       &randomsize, 
			       &randomsead));
  
  Crypto_Init(randomsead, randomsize);
  TPMTRYRETURN( TCS_FreeMemory (vtpm_globals->manager_tcs_handle, randomsead)); 
	
  // Create OIAP session for service's authorized commands
  TPMTRYRETURN( VTSP_OIAP( vtpm_globals->manager_tcs_handle, 
			   &vtpm_globals->keyAuth) );
  vtpm_globals->keyAuth.fContinueAuthSession = TRUE;

  vtpm_globals->mig_keys = NULL;

  // If fails, create new Manager.
  serviceStatus = VTPM_LoadManagerData();
  if (serviceStatus == TPM_IOERROR) {
    vtpmloginfo(VTPM_LOG_VTPM, "Failed to read manager file. Assuming first time initialization.\n");
    TPMTRYRETURN( VTPM_Create_Manager() );    
    TPMTRYRETURN( VTPM_SaveManagerData() );
  } else if (serviceStatus != TPM_SUCCESS) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to read existing manager file");
    exit(1);
  }

  //Load Storage Key 
  TPMTRYRETURN( VTSP_LoadKey( vtpm_globals->manager_tcs_handle,
			      TPM_SRK_KEYHANDLE,
			      &vtpm_globals->storageKeyWrap,
			      &SRK_AUTH,
			      &vtpm_globals->storageKeyHandle,
			      &vtpm_globals->keyAuth,
			      &vtpm_globals->storageKey,
                              FALSE ) );

  // Create entry for Dom0 for control messages
  TPMTRYRETURN( VTPM_Handle_New_DMI(NULL) );
  
  goto egress;
  
 abort_egress:
 egress:
  
  return(status);
}

/////////////////////////////////////////////////////////////////////////////// 
void VTPM_Stop_Manager() {
  VTPM_DMI_RESOURCE *dmi_res;
  struct hashtable_itr *dmi_itr;
  
  // Close all the TCS contexts. TCS should evict keys based on this
  if (hashtable_count(vtpm_globals->dmi_map) > 0) {
    dmi_itr = hashtable_iterator(vtpm_globals->dmi_map);
    do {
      dmi_res = (VTPM_DMI_RESOURCE *) hashtable_iterator_value(dmi_itr);
      if (dmi_res->connected) 
	close_dmi( dmi_res ); // Not really interested in return code
      
    } while (hashtable_iterator_advance(dmi_itr));
		free (dmi_itr);
  }
  
  if ( VTPM_SaveManagerData() != TPM_SUCCESS ) 
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to save manager data.\n");

  TCS_CloseContext(vtpm_globals->manager_tcs_handle);
  TCS_destroy();
  
  hashtable_destroy(vtpm_globals->dmi_map, 1);
  free(vtpm_globals);
  
  Crypto_Exit();
	
  vtpmloginfo(VTPM_LOG_VTPM, "VTPM Manager stopped.\n");
}
