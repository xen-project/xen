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
// vtpm_migrator_if.c
// 
//  Provides functions to call open network connection & call
//  a function on the vtpm_migratord on the destination
//
// ==================================================================

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <malloc.h>

#include "tcg.h"
#include "buffer.h"
#include "log.h"
#include "bsg.h"
#include "vtpm_migrator.h"

static int sock_desc;


TPM_RESULT vtpm_migratord_open(char *server_address){

  TPM_RESULT status = TPM_FAIL;

  /* network variables */
  struct in_addr ip_addr;
  struct sockaddr_in server_addr;
  int addr_len;
  struct hostent *dns_info=NULL;

  /* set up connection to server*/
  dns_info = gethostbyname(server_address);
  ip_addr.s_addr = *((unsigned long *) dns_info->h_addr_list[0]);

  if(ip_addr.s_addr < 0) {
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  /* set up server variable */
  memset((char *)&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(VTPM_MIG_PORT);
  server_addr.sin_addr.s_addr = ip_addr.s_addr;

  /* open socket, make connection */
  sock_desc = socket(AF_INET, SOCK_STREAM, 0);

  if (sock_desc < 0 ) {
    status = TPM_IOERROR;
    goto abort_egress;
  }

  if (connect(sock_desc,
              (struct sockaddr *)&server_addr,
              sizeof(server_addr)) < 0 ) {
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  status = TPM_SUCCESS;
  goto egress;

 abort_egress:
 egress:

  return status;
}

void vtpm_migratord_close() {
  close(sock_desc);
}


TPM_RESULT vtpm_migratord_command(TPM_COMMAND_CODE ord,
                                buffer_t *command_param_buf,
                                TPM_RESULT *cmd_status, /* out */
                                buffer_t *result_param_buf) {

  TPM_RESULT status = TPM_FAIL;
  int  size_read, size_write, i;
  BYTE *command, response_header[VTPM_COMMAND_HEADER_SIZE];
  UINT32 dmi_id=0, command_size, out_param_size, adj_param_size;
  TPM_TAG tag=VTPM_MTAG_REQ;

  if ( (!command_param_buf) || (!result_param_buf) || (!cmd_status) ) {
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }   
  
  command_size = VTPM_COMMAND_HEADER_SIZE + buffer_len(command_param_buf);
  command = (BYTE *) malloc( command_size );
  if (!command) {
    status = TPM_RESOURCES;
    goto abort_egress;
  }

  BSG_PackList(command, 3,
                 BSG_TPM_TAG, &tag,
                 BSG_TYPE_UINT32, &command_size,
                 BSG_TPM_COMMAND_CODE, &ord );

  memcpy(command + VTPM_COMMAND_HEADER_SIZE, command_param_buf->bytes, buffer_len(command_param_buf));

  size_write = write(sock_desc, command, command_size);

  if (size_write > 0) {
    vtpmloginfo(VTPM_LOG_VTPM_DEEP, "SENT (MIGd): 0x");
    for (i=0; i< command_size; i++) {
      vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", command[i]);
    }
    vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "\n");
  } else {
    vtpmlogerror(VTPM_LOG_VTPM, "Error writing to migration server via network.\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }

  if (size_write != (int) command_size )
    vtpmlogerror(VTPM_LOG_VTPM, "Could not write entire command to migration server (%d/%d)\n", size_write, command_size);

  // Read header for response 
  size_read = read(sock_desc, response_header, VTPM_COMMAND_HEADER_SIZE);
  if (size_read > 0) {
    vtpmloginfo(VTPM_LOG_VTPM_DEEP, "RECV (MIGd): 0x");
    for (i=0; i<size_read; i++)
      vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", response_header[i]);

  } else {
    vtpmlogerror(VTPM_LOG_VTPM, "Error reading from Migration Server.\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }

  if (size_read < (int) VTPM_COMMAND_HEADER_SIZE) {
    vtpmlogerror(VTPM_LOG_VTPM, "Command from migration server shorter than std header.\n");
    status = TPM_IOERROR;
    goto abort_egress;
  }

  // Unpack response from DMI for TPM command
  BSG_UnpackList(response_header, 3,
                 BSG_TPM_TAG, &tag,
                 BSG_TYPE_UINT32, &out_param_size,
                 BSG_TPM_COMMAND_CODE, cmd_status );

  // If response has parameters, read them.
  adj_param_size = out_param_size - VTPM_COMMAND_HEADER_SIZE;
  if (adj_param_size > 0) {
    TPMTRYRETURN( buffer_init( result_param_buf, adj_param_size, NULL) );
    size_read = read(sock_desc, result_param_buf->bytes, adj_param_size);
    if (size_read > 0) {
      for (i=0; i< size_read; i++)
        vtpmloginfomore(VTPM_LOG_VTPM_DEEP, "%x ", result_param_buf->bytes[i]);

    } else {
      vtpmlogerror(VTPM_LOG_VTPM, "Error reading from migration server.\n");
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


