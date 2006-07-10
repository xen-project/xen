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
// vtpm_manager_if.c
// 
//  Provides functions to call local vtpm manager interface (Hotplug)
//
// ==================================================================

#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>

#include "tcg.h"
#include "buffer.h"
#include "log.h"
#include "vtpm_ipc.h"
#include "bsg.h"
#include "vtpm_migrator.h"
#include "vtpm_manager.h"

#define VTPM_TX_HP_FNAME       "/var/vtpm/fifos/from_console.fifo"
#define VTPM_RX_HP_FNAME       "/var/vtpm/fifos/to_console.fifo"

static vtpm_ipc_handle_t tx_ipc_h, rx_ipc_h;

TPM_RESULT vtpm_manager_open(){

  if ( (vtpm_ipc_init(&tx_ipc_h,  VTPM_TX_HP_FNAME, O_RDWR, TRUE) != 0) ||  //FIXME: wronly
       (vtpm_ipc_init(&rx_ipc_h,  VTPM_RX_HP_FNAME, O_RDWR, TRUE) != 0) ) { //FIXME: rdonly
    vtpmlogerror(VTPM_LOG_VTPM, "Unable to connect to vtpm_manager.\n");
    return TPM_IOERROR;
  } 

  return TPM_SUCCESS;
}

void vtpm_manager_close() {

  vtpm_ipc_close(&tx_ipc_h);
  vtpm_ipc_close(&rx_ipc_h);
}


TPM_RESULT vtpm_manager_command(TPM_COMMAND_CODE ord,
                                buffer_t *command_param_buf,
                                TPM_RESULT *cmd_status, /* out */
                                buffer_t *result_param_buf) {

  TPM_RESULT status = TPM_FAIL;
  int  size_read, size_write, i;
  BYTE *adj_command, response_header[VTPM_COMMAND_HEADER_SIZE_SRV];
  UINT32 dmi_id=0, adj_command_size, out_param_size, adj_param_size;
  TPM_TAG tag=VTPM_TAG_REQ;

  if ( (!command_param_buf) || (!result_param_buf) || (!cmd_status) ) {
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }   
  
  adj_command_size = VTPM_COMMAND_HEADER_SIZE_SRV + buffer_len(command_param_buf);
  adj_command = (BYTE *) malloc( adj_command_size );
  if (!adj_command) {
    status = TPM_RESOURCES;
    goto abort_egress;
  }

  out_param_size = VTPM_COMMAND_HEADER_SIZE + buffer_len(command_param_buf);
  BSG_PackList(adj_command, 4,
                 BSG_TYPE_UINT32, &dmi_id,
                 BSG_TPM_TAG, &tag,
                 BSG_TYPE_UINT32, &out_param_size,
                 BSG_TPM_COMMAND_CODE, &ord );

  memcpy(adj_command + VTPM_COMMAND_HEADER_SIZE_SRV, command_param_buf->bytes, buffer_len(command_param_buf));

  size_write = vtpm_ipc_write(&tx_ipc_h, NULL, adj_command, adj_command_size);

  if (size_write > 0) {
    vtpmloginfo(VTPM_LOG_VTPM_DEEP, "SENT (MGR): 0x");
    for (i=0; i< adj_command_size; i++) {
      vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", adj_command[i]);
    }
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
  } else {
    vtpmlogerror(VTPM_LOG_VTPM, "Error writing VTPM Manager console.\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }

  if (size_write != (int) adj_command_size )
    vtpmlogerror(VTPM_LOG_VTPM, "Could not write entire command to mgr (%d/%d)\n", size_write, adj_command_size);

  // Read header for response to manager command
  size_read = vtpm_ipc_read(&rx_ipc_h, NULL, response_header, VTPM_COMMAND_HEADER_SIZE_SRV);
  if (size_read > 0) {
    vtpmloginfo(VTPM_LOG_VTPM_DEEP, "RECV (MGR): 0x");
    for (i=0; i<size_read; i++)
      vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", response_header[i]);

  } else {
    vtpmlogerror(VTPM_LOG_VTPM, "Error reading from vtpm manager.\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }

  if (size_read < (int) VTPM_COMMAND_HEADER_SIZE_SRV) {
    vtpmlogerror(VTPM_LOG_VTPM, "Command from vtpm_manager shorter than std header.\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }

  // Unpack response from DMI for TPM command
  BSG_UnpackList(response_header, 4,
                 BSG_TYPE_UINT32, &dmi_id,
                 BSG_TPM_TAG, &tag,
                 BSG_TYPE_UINT32, &out_param_size,
                 BSG_TPM_COMMAND_CODE, cmd_status );

  // If response has parameters, read them.
  // Note that out_param_size is in the client's context
  adj_param_size = out_param_size - VTPM_COMMAND_HEADER_SIZE;
  if (adj_param_size > 0) {
    TPMTRYRETURN( buffer_init( result_param_buf, adj_param_size, NULL) );
    size_read = vtpm_ipc_read(&rx_ipc_h, NULL, result_param_buf->bytes, adj_param_size);
    if (size_read > 0) {
      for (i=0; i< size_read; i++)
        vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", result_param_buf->bytes[i]);

    } else {
      vtpmlogerror(VTPM_LOG_VTPM, "Error reading from vtpm manager.\n");
      goto abort_egress;
    }
    vtpmloginfomore(VTPM_LOG_VTPM, "\n");

    if (size_read < (int)adj_param_size) {
      vtpmloginfomore(VTPM_LOG_VTPM, "\n");
      vtpmlogerror(VTPM_LOG_VTPM, "Command read(%d) is shorter than header indicates(%d).\n", size_read, adj_param_size);
      status = TPM_IOERROR;
      goto abort_egress;
    }
  } else {
    vtpmloginfomore(VTPM_LOG_VTPM, "\n");
  }

  status=TPM_SUCCESS;
  goto egress;

 abort_egress:
 egress:

  return status;
}


