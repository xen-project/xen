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

#ifndef VTPM_MUTLI_VM
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <fcntl.h>
 #include <signal.h>
 #include <wait.h>
#endif

#include "vtpmpriv.h"
#include "bsg.h"
#include "buffer.h"
#include "log.h"
#include "hashtable.h"
#include "hashtable_itr.h"

#define TPM_EMULATOR_PATH "/usr/bin/vtpmd"

TPM_RESULT close_dmi( VTPM_DMI_RESOURCE *dmi_res) {
  TPM_RESULT status = TPM_FAIL;
  
  if (dmi_res == NULL) 
    return TPM_SUCCESS;

  status = TCS_CloseContext(dmi_res->TCSContext);
  free ( dmi_res->NVMLocation );
  dmi_res->connected = FALSE;

#ifndef VTPM_MULTI_VM	
  free(dmi_res->guest_tx_fname);
  free(dmi_res->vtpm_tx_fname);
	  
  close(dmi_res->guest_tx_fh); dmi_res->guest_tx_fh = -1;
  close(dmi_res->vtpm_tx_fh);  dmi_res->vtpm_tx_fh = -1; 
  vtpm_globals->connected_dmis--;

  if (vtpm_globals->connected_dmis == 0) {
    // No more DMI's connected. Close fifo to prevent a broken pipe.
    close(vtpm_globals->guest_rx_fh);
    vtpm_globals->guest_rx_fh = -1;
  }
 #ifndef MANUAL_DM_LAUNCH
  if (dmi_res->dmi_id != VTPM_CTL_DM) {
    if (dmi_res->dmi_pid != 0) {
      vtpmloginfo(VTPM_LOG_VTPM, "Killing dmi on pid %d.\n", dmi_res->dmi_pid);
      if (kill(dmi_res->dmi_pid, SIGKILL) !=0) {
        vtpmloginfo(VTPM_LOG_VTPM, "DMI on pid %d is already dead.\n", dmi_res->dmi_pid);
      } else if (waitpid(dmi_res->dmi_pid, NULL, 0) != dmi_res->dmi_pid) {
        vtpmlogerror(VTPM_LOG_VTPM, "DMI on pid %d failed to stop.\n", dmi_res->dmi_pid);
        status = TPM_FAIL;
      }
    } else { 
      vtpmlogerror(VTPM_LOG_VTPM, "Could not kill dmi because it's pid was 0.\n");
      status = TPM_FAIL;
    }
  }
 #endif
#endif

  return status;
}
	
TPM_RESULT VTPM_Handle_New_DMI( const buffer_t *param_buf) {
  
  VTPM_DMI_RESOURCE *new_dmi=NULL;
  TPM_RESULT status=TPM_FAIL;
  BYTE type;
  UINT32 dmi_id, domain_id, *dmi_id_key; 

#ifndef VTPM_MULTI_VM
  int fh;
  char dmi_id_str[11]; // UINT32s are up to 10 digits + NULL
  struct stat file_info;
#endif
  
  if (param_buf == NULL) { // Assume creation of Dom 0 control
    type = 0;
    domain_id = VTPM_CTL_DM;
    dmi_id = VTPM_CTL_DM;
  } else if (buffer_len(param_buf) != sizeof(BYTE) + sizeof(UINT32) *2) {
    vtpmloginfo(VTPM_LOG_VTPM, "New DMI command wrong length: %d.\n", buffer_len(param_buf));
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  } else {
    vtpm_globals->connected_dmis++; // Put this here so we don't count Dom0
    BSG_UnpackList( param_buf->bytes, 3,
		    BSG_TYPE_BYTE, &type,
		    BSG_TYPE_UINT32, &domain_id,
		    BSG_TYPE_UINT32,  &dmi_id);
  }
  
  new_dmi = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi_id);
  if (new_dmi == NULL) { 
    vtpmloginfo(VTPM_LOG_VTPM, "Creating new DMI instance %d attached on domain %d.\n", dmi_id, domain_id);
    // Brand New DMI. Initialize the persistent pieces
    if ((new_dmi = (VTPM_DMI_RESOURCE *) malloc (sizeof(VTPM_DMI_RESOURCE))) == NULL) {
      status = TPM_RESOURCES;
      goto abort_egress;
    }
    memset(new_dmi, 0, sizeof(VTPM_DMI_RESOURCE));
    new_dmi->dmi_id = dmi_id;
    new_dmi->connected = FALSE;
    
    if ((dmi_id_key = (UINT32 *) malloc (sizeof(UINT32))) == NULL) {
      status = TPM_RESOURCES;
      goto abort_egress;
    }      
    *dmi_id_key = new_dmi->dmi_id;
    
    // install into map
    if (!hashtable_insert(vtpm_globals->dmi_map, dmi_id_key, new_dmi)){
      free(new_dmi);
      free(dmi_id_key);
      status = TPM_FAIL;
      goto egress;
    }
    
  } else 
    vtpmloginfo(VTPM_LOG_VTPM, "Re-attaching DMI instance %d on domain %d .\n", dmi_id, domain_id);
  
  if (new_dmi->connected) {
    vtpmlogerror(VTPM_LOG_VTPM, "Attempt to re-attach, currently attached instance %d. Ignoring\n", dmi_id);
    status = TPM_BAD_PARAMETER;
    goto egress;
  }
  
  // Initialize the Non-persistent pieces
  new_dmi->dmi_domain_id = domain_id;
  new_dmi->NVMLocation = NULL;
  
  new_dmi->TCSContext = 0;
  TPMTRYRETURN( TCS_OpenContext(&new_dmi->TCSContext) );
  
  new_dmi->NVMLocation = (char *) malloc(11 + strlen(DMI_NVM_FILE));
  sprintf(new_dmi->NVMLocation, DMI_NVM_FILE, (uint32_t) new_dmi->dmi_id);
  
  // Measure DMI
  // FIXME: This will measure DMI. Until then use a fixed DMI_Measurement value
  /*
  fh = open(TPM_EMULATOR_PATH, O_RDONLY);
  stat_ret = fstat(fh, &file_stat);
  if (stat_ret == 0) 
    dmi_size = file_stat.st_size;
  else {
      vtpmlogerror(VTPM_LOG_VTPM, "Could not open tpm_emulator!!\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }
  dmi_buffer
  */
  memset(&new_dmi->DMI_measurement, 0xcc, sizeof(TPM_DIGEST));
  
#ifndef VTPM_MULTI_VM
  if (dmi_id != VTPM_CTL_DM) {
    // Create a pair of fifo pipes
    if( (new_dmi->guest_tx_fname = (char *) malloc(11 + strlen(GUEST_TX_FIFO))) == NULL){ 
      status = TPM_RESOURCES;
      goto abort_egress;
    }
    sprintf(new_dmi->guest_tx_fname, GUEST_TX_FIFO, (uint32_t) dmi_id);
    
    if ((new_dmi->vtpm_tx_fname = (char *) malloc(11 + strlen(VTPM_TX_FIFO))) == NULL) {
      status = TPM_RESOURCES;
      goto abort_egress;
    }
    sprintf(new_dmi->vtpm_tx_fname, VTPM_TX_FIFO, (uint32_t) dmi_id);
    
    new_dmi->guest_tx_fh = -1;
    new_dmi->vtpm_tx_fh= -1;
    
    if ( stat(new_dmi->guest_tx_fname, &file_info) == -1) {
      if ( mkfifo(new_dmi->guest_tx_fname, S_IWUSR | S_IRUSR ) ){
	vtpmlogerror(VTPM_LOG_VTPM, "Failed to create dmi fifo.\n");
	status = TPM_IOERROR;
	goto abort_egress;
      }
    }
            
    if ( (fh = open(new_dmi->vtpm_tx_fname, O_RDWR)) == -1) {
      if ( mkfifo(new_dmi->vtpm_tx_fname, S_IWUSR | S_IRUSR ) ) {
	vtpmlogerror(VTPM_LOG_VTPM, "Failed to create dmi fifo.\n");
	status = TPM_IOERROR;
	goto abort_egress;
      }
    }
                
    // Launch DMI
    sprintf(dmi_id_str, "%d", (int) dmi_id);
#ifdef MANUAL_DM_LAUNCH
    vtpmlogerror(VTPM_LOG_VTPM, "FAKING starting vtpm with dmi=%s\n", dmi_id_str);
    new_dmi->dmi_pid = 0;
#else
    pid_t pid = fork();
    
    if (pid == -1) {
      vtpmlogerror(VTPM_LOG_VTPM, "Could not fork to launch vtpm\n");
      status = TPM_RESOURCES;
      goto abort_egress;
    } else if (pid == 0) {
      if ( stat(new_dmi->NVMLocation, &file_info) == -1)
	execl (TPM_EMULATOR_PATH, "vtmpd", "clear", dmi_id_str, NULL);
      else 
	execl (TPM_EMULATOR_PATH, "vtpmd", "save", dmi_id_str, NULL);
			
      // Returning from these at all is an error.
      vtpmlogerror(VTPM_LOG_VTPM, "Could not exec to launch vtpm\n");
    } else {
      new_dmi->dmi_pid = pid;
      vtpmloginfo(VTPM_LOG_VTPM, "Launching DMI on PID = %d\n", pid);
    }
#endif // MANUAL_DM_LAUNCH
  }
#else // VTPM_MUTLI_VM
  // FIXME: Measure DMI through call to Measurement agent in platform.
#endif 
	
  vtpm_globals->DMI_table_dirty = TRUE;
  new_dmi->connected = TRUE;  
  status=TPM_SUCCESS;
  goto egress;
  
 abort_egress:
  vtpmlogerror(VTPM_LOG_VTPM, "Failed to create DMI id=%d due to status=%s. Cleaning.\n", dmi_id, tpm_get_error_name(status));
  close_dmi( new_dmi );
	
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
  
	//TODO: Automatically delete file dmi_res->NVMLocation
  
  // Close DMI first
  TPMTRYRETURN(close_dmi( dmi_res ));
	free ( dmi_res );
	
  status=TPM_SUCCESS;    
  goto egress;
  
 abort_egress:
 egress:
  
  return status;
}
