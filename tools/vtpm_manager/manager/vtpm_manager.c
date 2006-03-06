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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#ifndef VTPM_MULTI_VM
#include <pthread.h>
#include <errno.h>
#include <aio.h>
#include <time.h>
#endif

#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "vtsp.h"
#include "bsg.h"
#include "hashtable.h"
#include "hashtable_itr.h"

#include "log.h"
#include "buffer.h"

VTPM_GLOBALS *vtpm_globals=NULL;

#ifdef VTPM_MULTI_VM
 #define vtpmhandlerloginfo(module,fmt,args...) vtpmloginfo (module, fmt, ##args );
 #define vtpmhandlerloginfomore(module,fmt,args...) vtpmloginfomore (module, fmt, ##args );
 #define vtpmhandlerlogerror(module,fmt,args...) vtpmlogerror (module, fmt, ##args );
#else 
 #define vtpmhandlerloginfo(module,fmt,args...) vtpmloginfo (module, "[%d]: " fmt, threadType, ##args );
 #define vtpmhandlerloginfomore(module,fmt,args...) vtpmloginfomore (module, fmt, ##args );
 #define vtpmhandlerlogerror(module,fmt,args...) vtpmlogerror (module, "[%d]: " fmt, threadType, ##args );
#endif

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

TPM_RESULT VTPM_Create_Service(){
  
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
  if (status == TPM_SUCCESS) { 
    vtpmloginfo(VTPM_LOG_VTPM, "Failed to readEK meaning TPM has an owner. Creating Keys off existing SRK.\n");
    TPMTRYRETURN(VTSP_TakeOwnership(vtpm_globals->manager_tcs_handle,
				    (const TPM_AUTHDATA*)&vtpm_globals->owner_usage_auth, 
				    &SRK_AUTH,
				    &ek_cryptoInfo,
				    &vtpm_globals->keyAuth)); 
  
    TPMTRYRETURN(VTSP_DisablePubekRead(vtpm_globals->manager_tcs_handle,
                                       (const TPM_AUTHDATA*)&vtpm_globals->owner_usage_auth,  
                                       &vtpm_globals->keyAuth));     
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
  goto egress;
  
 abort_egress:
  exit(1);
  
 egress:
  vtpmloginfo(VTPM_LOG_VTPM, "Finished initialized new VTPM service (Status = %d).\n", status);
  return status;
  
}


//////////////////////////////////////////////////////////////////////////////
#ifdef VTPM_MULTI_VM
int VTPM_Service_Handler(){
#else
void *VTPM_Service_Handler(void *threadTypePtr){
#endif
  TPM_RESULT      status =  TPM_FAIL; // Should never return
  UINT32          dmi, in_param_size, cmd_size, out_param_size, out_message_size, out_message_size_full;
  BYTE            *cmd_header, *in_param, *out_message;
  buffer_t        *command_buf=NULL, *result_buf=NULL;
  TPM_TAG         tag;
  TPM_COMMAND_CODE ord;
  VTPM_DMI_RESOURCE *dmi_res;
  int  size_read, size_write, i;
  
#ifndef VTPM_MULTI_VM
  UINT32 dmi_cmd_size;
  BYTE *dmi_cmd;
  int threadType = *(int *) threadTypePtr;
  
  // async io structures
  struct aiocb dmi_aio;
  struct aiocb *dmi_aio_a[1];
  dmi_aio_a[0] = &dmi_aio;
#endif
  
#ifdef DUMMY_BACKEND
  int dummy_rx;  
#endif
  
  cmd_header = (BYTE *) malloc(VTPM_COMMAND_HEADER_SIZE_SRV);
  command_buf = (buffer_t *) malloc(sizeof(buffer_t));
  result_buf = (buffer_t *) malloc(sizeof(buffer_t));
  
#ifndef VTPM_MULTI_VM
  TPM_RESULT *ret_value = (TPM_RESULT *) malloc(sizeof(TPM_RESULT));
#endif
  
  int *tx_fh, // Pointer to the filehandle this function will write to
      *rx_fh; // Pointer to the filehandle this function will read from
              // For a multi VM VTPM system, this function tx/rx with the BE
              //   via vtpm_globals->be_fh.
              // For a single VM system, the BE_LISTENER_THREAD tx/rx with theBE
              //   via vtpm_globals->be_fh, and the DMI_LISTENER_THREAD rx from
	      //   vtpm_globals->vtpm_rx_fh and tx to dmi_res->vtpm_tx_fh

  // Set rx_fh to point to the correct fh based on this mode.
#ifdef VTPM_MULTI_VM
  rx_fh = &vtpm_globals->be_fh;
#else
  if (threadType == BE_LISTENER_THREAD) {
 #ifdef DUMMY_BACKEND    
    dummy_rx = -1;
    rx_fh = &dummy_rx;
 #else
    rx_fh = &vtpm_globals->be_fh;
 #endif
  } else { // DMI_LISTENER_THREAD
    rx_fh = &vtpm_globals->vtpm_rx_fh;
  }
#endif
  
  // Set tx_fh to point to the correct fh based on this mode (If static)
  // Create any fifos that these fh will use.  
#ifndef VTPM_MULTI_VM
  int fh;
  if (threadType == BE_LISTENER_THREAD) {
    tx_fh = &vtpm_globals->be_fh;
    if ( (fh = open(GUEST_RX_FIFO, O_RDWR)) == -1) {
      if ( mkfifo(GUEST_RX_FIFO, S_IWUSR | S_IRUSR ) ){
        vtpmlogerror(VTPM_LOG_VTPM, "Unable to create FIFO: %s.\n", GUEST_RX_FIFO);        
	*ret_value = TPM_FAIL;
	pthread_exit(ret_value);
      }
    } else 
      close(fh);
    
  } else { // else DMI_LISTENER_THREAD
    // tx_fh will be set once the DMI is identified
    // But we need to make sure the read pip is created.
    if ( (fh = open(VTPM_RX_FIFO, O_RDWR)) == -1) {
      if ( mkfifo(VTPM_RX_FIFO, S_IWUSR | S_IRUSR ) ){
        vtpmlogerror(VTPM_LOG_VTPM, "Unable to create FIFO: %s.\n", VTPM_RX_FIFO);
	*ret_value = TPM_FAIL;
	pthread_exit(ret_value);
      }
    } else 
      close(fh);
    
  }
#else
  tx_fh = &vtpm_globals->be_fh;
#endif
  
  ////////////////////////// Main Loop //////////////////////////////////
  while(1) {
    
#ifdef VTPM_MULTI_VM
    vtpmhandlerloginfo(VTPM_LOG_VTPM, "Waiting for DMI messages.\n");
#else
    if (threadType == BE_LISTENER_THREAD) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM, "Waiting for Guest requests & ctrl messages.\n");
    } else    
      vtpmhandlerloginfo(VTPM_LOG_VTPM, "Waiting for DMI messages.\n");
#endif

    // Check status of rx_fh. If necessary attempt to re-open it.    
    char* s = NULL;
    if (*rx_fh < 0) {
#ifdef VTPM_MULTI_VM
      s = VTPM_BE_DEV;
#else
      if (threadType == BE_LISTENER_THREAD) 
  #ifdef DUMMY_BACKEND
	s = "/tmp/in.fifo";
  #else
      s = VTPM_BE_DEV;
  #endif
      else  // DMI Listener   
	s = VTPM_RX_FIFO;
      *rx_fh = open(s, O_RDWR);
#endif    
    }
    
    // Respond to failures to open rx_fh
    if (*rx_fh < 0) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Can't open inbound fh for %s.\n", s);
#ifdef VTPM_MULTI_VM
      return TPM_IOERROR; 
#else
      *ret_value = TPM_IOERROR;
      pthread_exit(ret_value);
#endif
    }
    
    // Read command header from rx_fh
    size_read = read(*rx_fh, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
    if (size_read > 0) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "RECV[%d}: 0x", size_read);
      for (i=0; i<size_read; i++) 
		vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);
    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Can't read from BE. Aborting... \n");
      close(*rx_fh);
      *rx_fh = -1;
      goto abort_command;
    }

    if (size_read < (int) VTPM_COMMAND_HEADER_SIZE_SRV) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "\n");
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Command shorter than normal header (%d bytes). Aborting...\n", size_read);
      goto abort_command;
    }
    
    // Unpack header
    BSG_UnpackList(cmd_header, 4,
		   BSG_TYPE_UINT32, &dmi,
		   BSG_TPM_TAG, &tag,
		   BSG_TYPE_UINT32, &in_param_size,
		   BSG_TPM_COMMAND_CODE, &ord );
    
    // Using the header info, read from rx_fh the parameters of the command
    // Note that in_param_size is in the client's context
    cmd_size = in_param_size - VTPM_COMMAND_HEADER_SIZE_CLT;
    if (cmd_size > 0) {
      in_param = (BYTE *) malloc(cmd_size);
      size_read = read( *rx_fh, in_param, cmd_size);
      if (size_read > 0) {
	for (i=0; i<size_read; i++) 
	  vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);
	
      } else {
        vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error reading from cmd. Aborting... \n");
	close(*rx_fh);
	*rx_fh = -1;
	goto abort_command;
      }
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
      
      if (size_read < (int) cmd_size) {
	vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
	vtpmhandlerlogerror(VTPM_LOG_VTPM, "Command read(%d) is shorter than header indicates(%d). Aborting...\n", size_read, cmd_size);
	goto abort_command;
      }
    } else {
      in_param = NULL;
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
    }            

#ifndef VTPM_MULTI_VM
    // It's illegal to receive a Dom0 command from a DMI.
    if ((threadType != BE_LISTENER_THREAD) && (dmi == 0)) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempt to access dom0 commands from DMI interface. Aborting...\n");
      goto abort_command;
    }
#endif
    
    // Fetch infomation about the DMI issuing the request.
    dmi_res = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi);
    if (dmi_res == NULL) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempted access to non-existent DMI in domain: %d. Aborting...\n", dmi);
      goto abort_command;
    }
    if (!dmi_res->connected) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempted access to disconnected DMI in domain: %d. Aborting...\n", dmi);
      goto abort_command;
    }

#ifndef VTPM_MULTI_VM
    // Now that we know which DMI this is, we can set the tx_fh handle.
    if (threadType != BE_LISTENER_THREAD) 
      tx_fh = &dmi_res->vtpm_tx_fh;
    // else we set this before the while loop since it doesn't change.
#endif 
   
    // Init the buffers used to handle the command and the response
    if ( (buffer_init_convert(command_buf, cmd_size, in_param) != TPM_SUCCESS) || 
	 (buffer_init(result_buf, 0, 0) != TPM_SUCCESS) ) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Failed to setup buffers. Aborting...\n");
      goto abort_command;
    }
    
    // Dispatch it as either control or user request.
    if (tag == VTPM_TAG_REQ) { 
      if (dmi_res->dmi_id == VTPM_CTL_DM){ 
	switch (ord) {
	case VTPM_ORD_OPEN:
	  status = VTPM_Handle_New_DMI(command_buf);
	  break;
          
	case VTPM_ORD_CLOSE:
	  status = VTPM_Handle_Close_DMI(command_buf);
	  break;
          
	case VTPM_ORD_DELETE:
	  status = VTPM_Handle_Delete_DMI(command_buf);
	  break;
	default:
	  status = TPM_BAD_ORDINAL; 
	} // switch
      } else {
	
	switch (ord) {                
	case VTPM_ORD_SAVENVM:
	  status= VTPM_Handle_Save_NVM(dmi_res,
				       command_buf, 
				       result_buf);
	  break;
	case VTPM_ORD_LOADNVM:
	  status= VTPM_Handle_Load_NVM(dmi_res, 
				       command_buf, 
				       result_buf);
	  break;
	  
	case VTPM_ORD_TPMCOMMAND:
	  status= VTPM_Handle_TPM_Command(dmi_res, 
					  command_buf, 
					  result_buf);
	  break;
	  
	default:
	  status = TPM_BAD_ORDINAL; 
	} // switch
      }
    } else { // This is not a VTPM Command at all.
	     // This happens in two cases. 
	     // MULTI_VM = A DMI illegally sent a raw TPM command to the manager
	     // Single VM:
	     //   BE_LISTENER_THREAD: Guest issued a TPM command.
	     //                       Send this to DMI and wait for response
	     //   DMI_LISTENER_THREAD: A DMI illegally sent a raw TPM command.
    
#ifdef VTPM_MULTI_VM
      // Raw TPM commands are not supported from the DMI
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempt to use unsupported direct access to TPM.\n");
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "Bad Command. dmi:%d, tag:%d, size:%d, ord:%d, Params: ", dmi, tag, in_param_size, ord);
      for (i=0; i<cmd_size; i++) 
	vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);
      
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
      status = TPM_FAIL;
    
#else
      // If BE_LISTENER_THREAD then this is a TPM command from a guest
      if (threadType == BE_LISTENER_THREAD) {
	// Dom0 can't talk to the BE, so this must be a broken FE/BE or badness
	if (dmi == 0) {
	  vtpmhandlerlogerror(VTPM_LOG_VTPM, "Illegal use of TPM command from dom0\n");
	  status = TPM_FAIL;
	} else {
	  vtpmhandlerloginfo(VTPM_LOG_VTPM, "Forwarding command to DMI.\n");
	  
	  // open the dmi_res->guest_tx_fh to send command to DMI
	  if (dmi_res->guest_tx_fh < 0)
	    dmi_res->guest_tx_fh = open(dmi_res->guest_tx_fname, O_WRONLY | O_NONBLOCK);

	  // handle failed opens dmi_res->guest_tx_fh        
	  if (dmi_res->guest_tx_fh < 0){
	    vtpmhandlerlogerror(VTPM_LOG_VTPM, "VTPM ERROR: Can't open outbound fh to dmi.\n");
	    status = TPM_IOERROR;
	    goto abort_with_error;
	  }        
          
	  //Forward TPM CMD stamped with dmi_id to DMI for handling
	  if (cmd_size) {
	    dmi_cmd = (BYTE *) malloc(VTPM_COMMAND_HEADER_SIZE_SRV + cmd_size);
	    dmi_cmd_size = VTPM_COMMAND_HEADER_SIZE_SRV + cmd_size;
	    memcpy(dmi_cmd, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
	    memcpy(dmi_cmd + VTPM_COMMAND_HEADER_SIZE_SRV, in_param, cmd_size);
	    size_write = write(dmi_res->guest_tx_fh, dmi_cmd, dmi_cmd_size);
	    
	    if (size_write > 0) {
	      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "SENT (DMI): 0x");
	      for (i=0; i<VTPM_COMMAND_HEADER_SIZE_SRV + cmd_size; i++) {
		vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", dmi_cmd[i]);
	      }
	      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
	    } else {
              vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error writing to DMI. Aborting... \n");
	      close(dmi_res->guest_tx_fh);
	      dmi_res->guest_tx_fh = -1;
              status = TPM_IOERROR;
	      goto abort_with_error;
	    }
	    free(dmi_cmd);
	  } else {
	    dmi_cmd_size = VTPM_COMMAND_HEADER_SIZE_SRV;
	    size_write = write(dmi_res->guest_tx_fh, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV );
	    if (size_write > 0) {
	      for (i=0; i<VTPM_COMMAND_HEADER_SIZE_SRV; i++) 
		vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);
	      
	      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
	    } else {
              vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error writing to DMI. Aborting... \n");
	      close(dmi_res->guest_tx_fh);
	      dmi_res->guest_tx_fh = -1;
              status = TPM_IOERROR;
	      goto abort_with_error;
	    }
	  }
         
	  if (size_write != (int) dmi_cmd_size) 
	    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Could not write entire command to DMI (%d/%d)\n", size_write, dmi_cmd_size);
	  buffer_free(command_buf);
	 
	  // Open vtpm_globals->guest_rx_fh to receive DMI response	  
	  if (vtpm_globals->guest_rx_fh < 0) 
	    vtpm_globals->guest_rx_fh = open(GUEST_RX_FIFO, O_RDONLY);
          
	  // Handle open failures
	  if (vtpm_globals->guest_rx_fh < 0){
	    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Can't open inbound fh to dmi.\n");
            status = TPM_IOERROR;
	    goto abort_with_error;
	  }                  
	  
	  // Read header for response to TPM command from DMI
          size_read = read( vtpm_globals->guest_rx_fh, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
	  if (size_read > 0) {
	    vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "RECV (DMI): 0x");
	    for (i=0; i<size_read; i++) 
	      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);
	    
	  } else {
            vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error reading from DMI. Aborting... \n");
	    close(vtpm_globals->guest_rx_fh);
	    vtpm_globals->guest_rx_fh = -1;
            status = TPM_IOERROR;
	    goto abort_with_error;
	  }
          
	  if (size_read < (int) VTPM_COMMAND_HEADER_SIZE_SRV) {
	    //vtpmdeepsublog("\n");
	    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Command from DMI shorter than normal header. Aborting...\n");
            status = TPM_IOERROR;
	    goto abort_with_error;
	  }
          
	  // Unpack response from DMI for TPM command
	  BSG_UnpackList(cmd_header, 4,
			 BSG_TYPE_UINT32, &dmi,
			 BSG_TPM_TAG, &tag,
			 BSG_TYPE_UINT32, &in_param_size,
			 BSG_TPM_COMMAND_CODE, &status );
        
	  // If response has parameters, read them.
	  // Note that in_param_size is in the client's context
	  cmd_size = in_param_size - VTPM_COMMAND_HEADER_SIZE_CLT;
	  if (cmd_size > 0) {
	    in_param = (BYTE *) malloc(cmd_size);
	    size_read = read( vtpm_globals->guest_rx_fh, in_param, cmd_size);
	    if (size_read > 0) {
	      for (i=0; i<size_read; i++) 
		vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);
	      
	    } else {
              vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error reading from BE. Aborting... \n");
	      close(vtpm_globals->guest_rx_fh);
	      vtpm_globals->guest_rx_fh = -1;
              status = TPM_IOERROR;
	      goto abort_with_error;
	    }
	    vtpmhandlerloginfomore(VTPM_LOG_VTPM, "\n");
            
	    if (size_read < (int)cmd_size) {
	      vtpmhandlerloginfomore(VTPM_LOG_VTPM, "\n");
	      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Command read(%d) from DMI is shorter than header indicates(%d). Aborting...\n", size_read, cmd_size);
              status = TPM_IOERROR;
	      goto abort_with_error;
	    }
	  } else {
	    in_param = NULL;
	    vtpmhandlerloginfomore(VTPM_LOG_VTPM, "\n");
	  }
          
	  if (buffer_init_convert(result_buf, cmd_size, in_param) != TPM_SUCCESS) {
	    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Failed to setup buffers. Aborting...\n");
            status = TPM_FAIL;
	    goto abort_with_error;
	  }
	  
	  vtpmhandlerloginfo(VTPM_LOG_VTPM, "Sending DMI's response to guest.\n");
	} // end else for if (dmi==0)
        
      } else { // This is a DMI lister thread. Thus this is from a DMI
	// Raw TPM commands are not supported from the DMI
	vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempt to use unsupported direct access to TPM.\n");
	vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "Bad Command. dmi:%d, tag:%d, size:%d, ord:%d, Params: ", dmi, tag, in_param_size, ord);
	for (i=0; i<cmd_size; i++) 
	  vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);
	
	vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
        
	status = TPM_FAIL;
      } // end else for if BE Listener
#endif
      
    } // end else for is VTPM Command

    // This marks the beginning of preparing response to be sent out.
    // Errors while handling responses jump here to reply with error messages
    // NOTE: Currently there are no recoverable errors in multi-VM mode. If one
    //       is added to the code, this ifdef should be removed.
    //       Also note this is NOT referring to errors in commands, but rather
    //       this is about I/O errors and such.
#ifndef VTPM_MULTI_VM
 abort_with_error:
#endif
    
    // Open tx_fh in preperation to send reponse back
    if (*tx_fh < 0) {
#ifdef VTPM_MULTI_VM
      *tx_fh = open(VTPM_BE_DEV, O_RDWR);
#else
      if (threadType == BE_LISTENER_THREAD) 
 #ifdef DUMMY_BACKEND
	*tx_fh = open("/tmp/out.fifo", O_RDWR);
 #else
        *tx_fh = open(VTPM_BE_DEV, O_RDWR);
 #endif
      else  // DMI Listener
	*tx_fh = open(dmi_res->vtpm_tx_fname, O_WRONLY);
#endif
      }

    
    // Handle failed open
    if (*tx_fh < 0) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "VTPM ERROR: Can't open outbound fh.\n");
#ifdef VTPM_MULTI_VM
      return TPM_IOERROR; 
#else
      *ret_value = TPM_IOERROR;
      pthread_exit(ret_value);
#endif
    }        
    
    // Prepend VTPM header with destination DM stamped
    out_param_size = buffer_len(result_buf);
    out_message_size = VTPM_COMMAND_HEADER_SIZE_CLT + out_param_size;
    out_message_size_full = VTPM_COMMAND_HEADER_SIZE_SRV + out_param_size;
    out_message = (BYTE *) malloc (out_message_size_full);
    
    BSG_PackList(out_message, 4,
		 BSG_TYPE_UINT32, (BYTE *) &dmi,
		 BSG_TPM_TAG, (BYTE *) &tag,
		 BSG_TYPE_UINT32, (BYTE *) &out_message_size,
		 BSG_TPM_RESULT, (BYTE *) &status);
    
    if (buffer_len(result_buf) > 0) 
      memcpy(out_message + VTPM_COMMAND_HEADER_SIZE_SRV, result_buf->bytes, out_param_size);
    
    
    //Note: Send message + dmi_id
    size_write = write(*tx_fh, out_message, out_message_size_full );
    if (size_write > 0) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "SENT: 0x");
      for (i=0; i < out_message_size_full; i++) 
	vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", out_message[i]);
      
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");            
    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error writing to BE. Aborting... \n");
      close(*tx_fh);
      *tx_fh = -1;
      goto abort_command;
    }
    free(out_message);
    
    if (size_write < (int)out_message_size_full) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Unable to write full command to BE (%d/%d)\n", size_write, out_message_size_full);
      goto abort_command;
    }
    
    // On certain failures an error message cannot be sent. 
    // This marks the beginning of cleanup in preperation for the next command.
  abort_command:
    //free buffers
    bzero(cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
    //free(in_param); // This was converted to command_buf. No need to free 
    if (command_buf != result_buf) 
      buffer_free(result_buf);
    
    buffer_free(command_buf);
    
#ifndef VTPM_MULTI_VM
    if (threadType != BE_LISTENER_THREAD) {
#endif
      if ( (vtpm_globals->DMI_table_dirty) &&
	   (VTPM_SaveService() != TPM_SUCCESS) ) {
	vtpmhandlerlogerror(VTPM_LOG_VTPM, "ERROR: Unable to save manager data.\n");
      }
#ifndef VTPM_MULTI_VM
    }
#endif
    
  } // End while(1)
  
}


///////////////////////////////////////////////////////////////////////////////
TPM_RESULT VTPM_Init_Service() {
  TPM_RESULT status = TPM_FAIL, serviceStatus;   
  BYTE *randomsead;
  UINT32 randomsize;

  if ((vtpm_globals = (VTPM_GLOBALS *) malloc(sizeof(VTPM_GLOBALS))) == NULL){
    status = TPM_FAIL;
    goto abort_egress;
  }
  memset(vtpm_globals, 0, sizeof(VTPM_GLOBALS));
  vtpm_globals->be_fh = -1;

#ifndef VTPM_MULTI_VM
  vtpm_globals->vtpm_rx_fh = -1;
  vtpm_globals->guest_rx_fh = -1;
  vtpm_globals->connected_dmis = 0;
#endif
  if ((vtpm_globals->dmi_map = create_hashtable(10, hashfunc32, equals32)) == NULL){
    status = TPM_FAIL;
    goto abort_egress;
  }
  
  vtpm_globals->DMI_table_dirty = FALSE;
  
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

	// If failed, create new Service.
  serviceStatus = VTPM_LoadService();
  if (serviceStatus == TPM_IOERROR) {
    vtpmloginfo(VTPM_LOG_VTPM, "Failed to read service file. Assuming first time initialization.\n");
    TPMTRYRETURN( VTPM_Create_Service() );    
  } else if (serviceStatus != TPM_SUCCESS) {
    vtpmlogerror(VTPM_LOG_VTPM, "Failed to read existing service file");
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
    
  // --------------------- Command handlers ---------------------------
  
  goto egress;
  
 abort_egress:
 egress:
  
  return(status);
}
 
void VTPM_Stop_Service() {
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
  
  if ( (vtpm_globals->DMI_table_dirty) && (VTPM_SaveService() != TPM_SUCCESS) )
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to save manager data.\n");

  TCS_CloseContext(vtpm_globals->manager_tcs_handle);
  TCS_destroy();
  
  hashtable_destroy(vtpm_globals->dmi_map, 1);
  free(vtpm_globals);
  
  close(vtpm_globals->be_fh);
  Crypto_Exit();
	
  vtpmloginfo(VTPM_LOG_VTPM, "VTPM Manager stopped.\n");
}
