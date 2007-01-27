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
#include "hashtable_itr.h"
#include "vtpm_ipc.h"

#define TPM_EMULATOR_PATH "/usr/bin/vtpmd"

// if dmi_res is non-null, then return a pointer to new object.
// Also, this does not fill in the measurements. They should be filled by
// design dependent code or saveNVM
TPM_RESULT init_dmi(UINT32 dmi_id, BYTE dmi_type, VTPM_DMI_RESOURCE **dmi_res) {

  TPM_RESULT status=TPM_SUCCESS;
  VTPM_DMI_RESOURCE *new_dmi=NULL;
  UINT32 *dmi_id_key=NULL;

  if ((new_dmi = (VTPM_DMI_RESOURCE *) malloc (sizeof(VTPM_DMI_RESOURCE))) == NULL) {
      status = TPM_RESOURCES;
      goto abort_egress;
  }
  memset(new_dmi, 0, sizeof(VTPM_DMI_RESOURCE));
  new_dmi->dmi_id = dmi_id;
  new_dmi->dmi_type = dmi_type;
  new_dmi->connected = FALSE;
  new_dmi->TCSContext = 0;

  new_dmi->NVMLocation = (char *) malloc(11 + strlen(DMI_NVM_FILE));
  sprintf(new_dmi->NVMLocation, DMI_NVM_FILE, (uint32_t) new_dmi->dmi_id);

  if ((dmi_id_key = (UINT32 *) malloc (sizeof(UINT32))) == NULL) {
    status = TPM_RESOURCES;
    goto abort_egress;
  }
  *dmi_id_key = new_dmi->dmi_id;

  // install into map
  if (!hashtable_insert(vtpm_globals->dmi_map, dmi_id_key, new_dmi)){
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to insert instance into table. Aborting.\n", dmi_id);
    status = TPM_FAIL;
    goto abort_egress;
  }

  if (dmi_res)
    *dmi_res = new_dmi;

  goto egress;

 abort_egress:
  if (new_dmi) {
    free(new_dmi->NVMLocation);
    free(new_dmi);
  }
  free(dmi_id_key);

 egress:
  return status;
}

TPM_RESULT close_dmi(VTPM_DMI_RESOURCE *dmi_res) {
  if (dmi_res == NULL) 
    return TPM_SUCCESS;

  if (dmi_res->dmi_id == VTPM_CTL_DM) 
    return(TPM_BAD_PARAMETER);

  TCS_CloseContext(dmi_res->TCSContext);
  dmi_res->connected = FALSE;

  vtpm_globals->connected_dmis--;

  return (VTPM_Close_DMI_Extra(dmi_res) );
}
	
TPM_RESULT VTPM_Handle_New_DMI(const buffer_t *param_buf) {
  
  VTPM_DMI_RESOURCE *new_dmi=NULL;
  TPM_RESULT status=TPM_FAIL;
  BYTE dmi_type, vm_type, startup_mode;
  UINT32 dmi_id; 

  if (param_buf == NULL) { // Assume creation of Dom 0 control
    dmi_type = VTPM_TYPE_NON_MIGRATABLE;
    dmi_id = VTPM_CTL_DM;
  } else if (buffer_len(param_buf) != sizeof(BYTE) * 3  + sizeof(UINT32)) {
    vtpmloginfo(VTPM_LOG_VTPM, "New DMI command wrong length: %d.\n", buffer_len(param_buf));
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  } else {
    vtpm_globals->connected_dmis++; // Put this here so we don't count Dom0
    BSG_UnpackList( param_buf->bytes, 4,
		    BSG_TYPE_BYTE, &dmi_type,
		    BSG_TYPE_BYTE, &startup_mode,
		    BSG_TYPE_BYTE, &vm_type,
		    BSG_TYPE_UINT32,  &dmi_id);
  }

  if ((dmi_type != VTPM_TYPE_NON_MIGRATABLE) && (dmi_type != VTPM_TYPE_MIGRATABLE)) {
    vtpmlogerror(VTPM_LOG_VTPM, "Creation of VTPM with illegal type.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  new_dmi = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi_id);
  if (new_dmi == NULL) { 
    vtpmloginfo(VTPM_LOG_VTPM, "Creating new DMI instance %d attached.\n", dmi_id );
    // Brand New DMI. Initialize the persistent pieces
    TPMTRYRETURN(init_dmi(dmi_id, dmi_type, &new_dmi) );  
  } else 
    vtpmloginfo(VTPM_LOG_VTPM, "Re-attaching DMI instance %d.\n", dmi_id);

  if (new_dmi->connected) {
    vtpmlogerror(VTPM_LOG_VTPM, "Attempt to re-attach, currently attached instance %d. Ignoring\n", dmi_id);
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
  
  if (new_dmi->dmi_type == VTPM_TYPE_MIGRATED) {
    vtpmlogerror(VTPM_LOG_VTPM, "Attempt to re-attach previously migrated instance %d without recovering first. Ignoring\n", dmi_id);
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  // Initialize the Non-persistent pieces
  TPMTRYRETURN( TCS_OpenContext(&new_dmi->TCSContext) );
  
  new_dmi->connected = TRUE;  

  // Design specific new DMI code. 
  // Includes: create IPCs, Measuring DMI, and maybe launching DMI
  TPMTRYRETURN(VTPM_New_DMI_Extra(new_dmi, vm_type, startup_mode) );
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to create DMI id=%d due to status=%s. Cleaning.\n", dmi_id, tpm_get_error_name(status));
  close_dmi(new_dmi );
	
 egress:
  return status;
}

TPM_RESULT VTPM_Handle_Close_DMI( const buffer_t *param_buf) {
  
  TPM_RESULT status=TPM_FAIL;
  VTPM_DMI_RESOURCE *dmi_res=NULL;
  UINT32 dmi_id;
  
  if ((param_buf == NULL) || (buffer_len(param_buf) != sizeof(UINT32)) ) {
    vtpmlogerror(VTPM_LOG_VTPM, "Closing DMI has bad size.");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
  
  BSG_UnpackList( param_buf->bytes, 1,
		  BSG_TYPE_UINT32, &dmi_id);
  
  vtpmloginfo(VTPM_LOG_VTPM, "Closing DMI %d.\n", dmi_id);
  
  dmi_res = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi_id);
  if (dmi_res == NULL ) {
    vtpmlogerror(VTPM_LOG_VTPM, "Trying to close nonexistent DMI.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
	
  if (!dmi_res->connected) {
    vtpmlogerror(VTPM_LOG_VTPM, "Closing non-connected DMI.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
  
  // Close Dmi
	TPMTRYRETURN(close_dmi( dmi_res ));
  
  status=TPM_SUCCESS;    
  goto egress;
  
 abort_egress:
 egress:
  
  return status;
}

TPM_RESULT VTPM_Handle_Delete_DMI( const buffer_t *param_buf) {
  
  TPM_RESULT status=TPM_FAIL;
  VTPM_DMI_RESOURCE *dmi_res=NULL;
  UINT32 dmi_id;
    
  if ((param_buf == NULL) || (buffer_len(param_buf) != sizeof(UINT32)) ) {
    vtpmlogerror(VTPM_LOG_VTPM, "Closing DMI has bad size.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
  
  BSG_UnpackList( param_buf->bytes, 1,
		  BSG_TYPE_UINT32, &dmi_id);
  
  vtpmloginfo(VTPM_LOG_VTPM, "Deleting DMI %d.\n", dmi_id);    
  
  dmi_res = (VTPM_DMI_RESOURCE *) hashtable_remove(vtpm_globals->dmi_map, &dmi_id);
  if (dmi_res == NULL) {
    vtpmlogerror(VTPM_LOG_VTPM, "Closing non-existent DMI.\n");
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }
  
  //vtpm scripts delete file dmi_res->NVMLocation for us
  
  // Close DMI first
  TPMTRYRETURN(close_dmi( dmi_res ));
  free ( dmi_res );
	
  status=TPM_SUCCESS;    
  goto egress;
  
 abort_egress:
 egress:
  
  return status;
}
