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
// vtpm_manager_handler.c
// 
//  This file will house the main logic of the VTPM Manager
//
// ==================================================================

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "vtsp.h"
#include "bsg.h"
#include "hashtable.h"
#include "hashtable_itr.h"
#include "log.h"
#include "buffer.h"

#define vtpmhandlerloginfo(module,fmt,args...) vtpmloginfo (module, "[%s]: " fmt, thread_name, ##args );
#define vtpmhandlerloginfomore(module,fmt,args...) vtpmloginfomore (module, fmt, ##args );
#define vtpmhandlerlogerror(module,fmt,args...) vtpmlogerror (module, "[%s]: " fmt, thread_name, ##args );

// ---------------------- Prototypes -------------------
TPM_RESULT vtpm_manager_handle_vtpm_cmd(VTPM_DMI_RESOURCE *dmi_res,
					TPM_COMMAND_CODE ord,
					buffer_t *command_buf,
					buffer_t *result_buf,
                                        BOOL is_priv,
                                        char *thread_name);

TPM_RESULT vtpm_manager_handle_tpm_cmd(vtpm_ipc_handle_t *tx_ipc_h,
                                       vtpm_ipc_handle_t *rx_ipc_h,
                                       VTPM_DMI_RESOURCE *dmi_res,
                                       BYTE *cmd_header,
                                       buffer_t *param_buf,
                                       buffer_t *result_buf,
                                       char *thread_name);

TPM_RESULT VTPM_Manager_Handler( vtpm_ipc_handle_t *tx_ipc_h, 
                                 vtpm_ipc_handle_t *rx_ipc_h,
                                 BOOL fw_tpm,   // Forward TPM cmds?
                                 vtpm_ipc_handle_t *fw_tx_ipc_h, 
                                 vtpm_ipc_handle_t *fw_rx_ipc_h,
                                 BOOL is_priv,
                                 char *thread_name) {
  TPM_RESULT      status =  TPM_FAIL; // Should never return
  UINT32          dmi, in_param_size, cmd_size, out_param_size, out_message_size, reply_size;
  BYTE            *cmd_header=NULL, *in_param=NULL, *out_message=NULL, *reply;
  buffer_t        *command_buf=NULL, *result_buf=NULL;
  TPM_TAG         tag;
  TPM_COMMAND_CODE ord;
  VTPM_DMI_RESOURCE *dmi_res;
  int  size_read, size_write, i;
  BOOL add_header=TRUE; // This indicates to prepend a header on result_buf before sending
  
  cmd_header = (BYTE *) malloc(VTPM_COMMAND_HEADER_SIZE_SRV);
  command_buf = (buffer_t *) malloc(sizeof(buffer_t));
  result_buf = (buffer_t *) malloc(sizeof(buffer_t));
 
  // ------------------------ Main Loop --------------------------------
  while(1) {
    
    vtpmhandlerloginfo(VTPM_LOG_VTPM, "%s waiting for messages.\n", thread_name);

    // --------------------- Read Cmd from Sender ----------------
    
    // Read command header 
    size_read = vtpm_ipc_read(rx_ipc_h, NULL, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
    if (size_read > 0) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "RECV[%d]: 0x", size_read);
      for (i=0; i<size_read; i++) 
	vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);
    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "%s can't read from ipc. Errono = %d. Aborting... \n", thread_name, errno);
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
    
    // Using the header info, read the parameters of the command
    // Note that in_param_size is in the client's context
    cmd_size = in_param_size - VTPM_COMMAND_HEADER_SIZE_CLT;
    if (cmd_size > 0) {
      in_param = (BYTE *) malloc(cmd_size);
      size_read = vtpm_ipc_read( rx_ipc_h, NULL, in_param, cmd_size);
      if (size_read > 0) {
	for (i=0; i<size_read; i++) 
	  vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);
	
      } else {
        vtpmhandlerlogerror(VTPM_LOG_VTPM, "%s had error reading cmd from ipc. Aborting... \n", thread_name);
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

    // Init the buffers used to handle the command and the response
    if ( (buffer_init_convert(command_buf, cmd_size, in_param) != TPM_SUCCESS) || 
	 (buffer_init(result_buf, 0, 0) != TPM_SUCCESS) ) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Failed to setup buffers. Aborting...\n");
      goto abort_command;
    }
    
    // -------------- Dispatch Commands to Handlers -----------
    if ((tag == VTPM_TAG_REQ) && (ord & VTPM_PRIV_MASK)) {
      vtpm_lock_wrlock();
    } else {
      vtpm_lock_rdlock();
    }

    if ( !(dmi_res = (VTPM_DMI_RESOURCE *) hashtable_search(vtpm_globals->dmi_map, &dmi)) ||
         (!dmi_res->connected) ) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempted access to non-existent or disconnected DMI %d. Aborting...\n", dmi);
      status = TPM_BAD_PARAMETER;
      // We have no one to reply to, they don't exist.
      goto abort_command;
    }

    if (tag == VTPM_TAG_REQ) { 
    
      status = vtpm_manager_handle_vtpm_cmd(dmi_res, ord, command_buf, result_buf, is_priv, thread_name);

    } else { // This is not a VTPM Command at all.
      if (fw_tpm) { 
        status = vtpm_manager_handle_tpm_cmd(fw_tx_ipc_h, fw_rx_ipc_h, dmi_res, cmd_header, command_buf, result_buf, thread_name);

        // This means calling the DMI failed, not that the cmd failed in the DMI
        // Since the return will be interpretted by a TPM app, all errors are IO_ERRORs to the app
        if (status != TPM_SUCCESS) { 
          status = TPM_IOERROR;
	  goto abort_with_error;
        }
        // Unlike all other commands, forwarded commands yield a result_buf that includes the DMI's status. This
        // should be forwarded to the caller VM
        add_header = FALSE;
      } else {
        // We are not supposed to forward TPM commands at all.
        int i;
        vtpmhandlerlogerror(VTPM_LOG_VTPM, "Attempt to use unsupported direct access to TPM.\n");
        vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "Bad Command. dmi:%d, tag:%d, size:%d, ord:%d, Params: ", dmi, tag, in_param_size, ord);
        for (i=0; i<cmd_size; i++)
          vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);

        vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");

        status = TPM_FAIL;
        goto abort_with_error;
     }

    } // end else for is VTPM Command

    // ------------------- Respond to Sender ------------------

    // Errors while handling responses jump here to reply with error messages
    // NOTE: Currently there are no recoverable errors in multi-VM mode. If one
    //       is added to the code, this ifdef should be removed.
    //       Also note this is NOT referring to errors in commands, but rather
    //       this is about I/O errors and such.
#ifndef VTPM_MULTI_VM
 abort_with_error:
#endif
   
    if (add_header) { 
      // Prepend VTPM header with destination DM stamped
      out_param_size = buffer_len(result_buf);
      out_message_size = VTPM_COMMAND_HEADER_SIZE_CLT + out_param_size;
      reply_size = VTPM_COMMAND_HEADER_SIZE_SRV + out_param_size;
      out_message = (BYTE *) malloc (reply_size);
      reply = out_message;
    
      BSG_PackList(out_message, 4,
		   BSG_TYPE_UINT32, (BYTE *) &dmi,
		   BSG_TPM_TAG, (BYTE *) &tag,
		   BSG_TYPE_UINT32, (BYTE *) &out_message_size,
		   BSG_TPM_RESULT, (BYTE *) &status);
    
      if (buffer_len(result_buf) > 0) 
        memcpy(out_message + VTPM_COMMAND_HEADER_SIZE_SRV, result_buf->bytes, out_param_size);
      //Note: Send message + dmi_id
    } else {
      reply = result_buf->bytes;
      reply_size = buffer_len(result_buf);
    }  
    size_write = vtpm_ipc_write(tx_ipc_h, (dmi_res ? dmi_res->tx_vtpm_ipc_h : NULL), reply, reply_size );
    if (size_write > 0) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "SENT: 0x");
      for (i=0; i < reply_size; i++) 
	vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", reply[i]);
      
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");            
    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "%s had error writing to ipc. Aborting... \n", thread_name);
      goto abort_command;
    }
    free(out_message); out_message=NULL;
    
    if (size_write < (int)reply_size) {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "%s unable to write full command to ipc (%d/%d)\n", thread_name, size_write, reply_size);
      goto abort_command;
    }
    
    // On certain failures an error message cannot be sent. 
    // This marks the beginning of cleanup in preperation for the next command.
  abort_command:
    //free buffers
    bzero(cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
    //free(in_param); // This was converted to command_buf. No need to free 
    buffer_free(result_buf);
    buffer_free(command_buf);

    // If we have a write lock, save the manager table
    if ((tag == VTPM_TAG_REQ) && (ord & VTPM_PRIV_MASK) &&
        (VTPM_SaveManagerData() != TPM_SUCCESS) ) {
       vtpmhandlerlogerror(VTPM_LOG_VTPM, "ERROR: Unable to save manager data.\n");
    }

    vtpm_lock_unlock();
    add_header = TRUE; // Reset to the default
  } // End while(1)
  
}

/////////////////////////////////////////////////////////////////////////
TPM_RESULT vtpm_manager_handle_vtpm_cmd(VTPM_DMI_RESOURCE *dmi_res, 
					TPM_COMMAND_CODE ord,
					buffer_t *command_buf,
					buffer_t *result_buf,
                                        BOOL is_priv,
                                        char *thread_name) {

  TPM_RESULT status = TPM_FAIL;

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

  case VTPM_ORD_GET_MIG_KEY:
    status = VTPM_Handle_Get_Migration_key(command_buf, 
                                           result_buf);
    break;

  case VTPM_ORD_LOAD_MIG_KEY:
    status = VTPM_Handle_Load_Migration_key(command_buf, 
                                           result_buf);
    break;
   
  default:
    // Privileged handlers can do maintanance
    if (is_priv) {
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

      case VTPM_ORD_MIGRATE_IN:
        status = VTPM_Handle_Migrate_In(command_buf, result_buf);
        break;

      case VTPM_ORD_MIGRATE_OUT:
        status = VTPM_Handle_Migrate_Out(command_buf, result_buf);
        break;

      default:
        status = TPM_BAD_ORDINAL;
      } // switch
    } else { // is priv command

        status = TPM_BAD_ORDINAL;
    } // inner switch
  } // outer switch

  return(status);
}
      
/////////////////////////////////////////////////////////////////////
TPM_RESULT vtpm_manager_handle_tpm_cmd(vtpm_ipc_handle_t *tx_ipc_h,
                                       vtpm_ipc_handle_t *rx_ipc_h,
				       VTPM_DMI_RESOURCE *dmi_res, 
				       BYTE *cmd_header,
				       buffer_t *param_buf,
				       buffer_t *result_buf,
                                       char *thread_name) {

  TPM_RESULT status = TPM_FAIL;
  UINT32 dmi_dst;
  TPM_COMMAND_CODE ord;
  TPM_TAG tag_out;
  UINT32 dmi_cmd_size, in_param_size, adj_param_size;
  BYTE *dmi_cmd, *in_param;
  int  size_read, size_write, i;

  //// Dom0 can't talk to the BE, so this must be a broken FE/BE or badness
  if (dmi_res->dmi_id == VTPM_CTL_DM) {
    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Illegal use of TPM command from dom0\n");
    status = TPM_FAIL;
    goto abort_with_error;
  } 

  vtpmhandlerloginfo(VTPM_LOG_VTPM, "Forwarding command to DMI.\n");
   
  //Forward TPM CMD stamped with dmi_id to DMI for handling
  if (buffer_len(param_buf)) {
    dmi_cmd = (BYTE *) malloc(VTPM_COMMAND_HEADER_SIZE_SRV + buffer_len(param_buf));
    dmi_cmd_size = VTPM_COMMAND_HEADER_SIZE_SRV + buffer_len(param_buf);
    memcpy(dmi_cmd, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
    memcpy(dmi_cmd + VTPM_COMMAND_HEADER_SIZE_SRV, param_buf->bytes, buffer_len(param_buf));
    size_write = vtpm_ipc_write(tx_ipc_h, dmi_res->tx_tpm_ipc_h, dmi_cmd, dmi_cmd_size);

    if (size_write > 0) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "SENT (DMI): 0x");
      for (i=0; i<VTPM_COMMAND_HEADER_SIZE_SRV + buffer_len(param_buf); i++) {
        vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", dmi_cmd[i]);
      }
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error writing to DMI. Aborting... \n");
      status = TPM_IOERROR;
      goto abort_with_error;
    }
    free(dmi_cmd);
  } else {
    dmi_cmd_size = VTPM_COMMAND_HEADER_SIZE_SRV;
    size_write = vtpm_ipc_write(tx_ipc_h, dmi_res->tx_tpm_ipc_h, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV );
    if (size_write > 0) {
      vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "SENT (DMI): 0x");
      for (i=0; i<VTPM_COMMAND_HEADER_SIZE_SRV; i++) 
        vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);

      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error writing to DMI. Aborting... \n");
      status = TPM_IOERROR;
      goto abort_with_error;
    }
  }
    
  if (size_write != (int) dmi_cmd_size) 
    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Could not write entire command to DMI (%d/%d)\n", size_write, dmi_cmd_size);

  buffer_free(param_buf);
  
  // Read header for response to TPM command from DMI
  size_read = vtpm_ipc_read( rx_ipc_h, dmi_res->rx_tpm_ipc_h, cmd_header, VTPM_COMMAND_HEADER_SIZE_SRV);
  if (size_read > 0) {
    vtpmhandlerloginfo(VTPM_LOG_VTPM_DEEP, "RECV (DMI): 0x");
    for (i=0; i<size_read; i++) 
      vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", cmd_header[i]);

  } else {
    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error reading from DMI. Aborting... \n");
    status = TPM_IOERROR;
    goto abort_with_error;
  }
  
  if (size_read < (int) VTPM_COMMAND_HEADER_SIZE_SRV) {
    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Command from DMI shorter than normal header. Aborting...\n");
    status = TPM_IOERROR;
    goto abort_with_error;
  }

  // Unpack response from DMI for TPM command
  BSG_UnpackList(cmd_header, 4,
                 BSG_TYPE_UINT32, &dmi_dst,
                 BSG_TPM_TAG, &tag_out,
                 BSG_TYPE_UINT32, &in_param_size,
                 BSG_TPM_COMMAND_CODE, &status );
  
  // If response has parameters, read them.
  // Note that in_param_size is in the client's context
  adj_param_size = in_param_size - VTPM_COMMAND_HEADER_SIZE_CLT;
  if (adj_param_size > 0) {
    in_param = (BYTE *) malloc(adj_param_size);
    size_read = vtpm_ipc_read(rx_ipc_h, dmi_res->rx_tpm_ipc_h, in_param, adj_param_size);
    if (size_read > 0) {
      for (i=0; i<size_read; i++) 
        vtpmhandlerloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", in_param[i]);

    } else {
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Error reading from BE. Aborting... \n");
      goto abort_with_error;
    }
    vtpmhandlerloginfomore(VTPM_LOG_VTPM, "\n");
   
    if (size_read < (int)adj_param_size) {
      vtpmhandlerloginfomore(VTPM_LOG_VTPM, "\n");
      vtpmhandlerlogerror(VTPM_LOG_VTPM, "Command read(%d) from DMI is shorter than header indicates(%d). Aborting...\n", size_read, adj_param_size);
      status = TPM_IOERROR;
      goto abort_with_error;
    }
  } else {
    in_param = NULL;
    vtpmhandlerloginfomore(VTPM_LOG_VTPM, "\n");
  }
   
  if ( (buffer_init(result_buf, VTPM_COMMAND_HEADER_SIZE_SRV, cmd_header) != TPM_SUCCESS) || 
       (buffer_append_raw(result_buf, adj_param_size, in_param) != TPM_SUCCESS) ) {
    vtpmhandlerlogerror(VTPM_LOG_VTPM, "Failed to setup buffers. Aborting...\n");
    status = TPM_FAIL;
    goto abort_with_error;
  }
 
  vtpmhandlerloginfo(VTPM_LOG_VTPM, "Sending DMI's response to guest.\n");

  status = TPM_SUCCESS;

 abort_with_error:

  return status;
}

