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

#include <stdlib.h>
#include <string.h>

#include "tcg.h"
#include "bsg.h"
#include "log.h"
#include "vtpm_migrator.h"
#include "vtpm_manager.h"

#define VTPM_SH_CMD_HDR  "bash -c \"cd /etc/xen/scripts; source /etc/xen/scripts/vtpm-common.sh;"
#define VTPM_SH_CMD_FTR  "\""
#define VTPM_SH_GETINST  "vtpmdb_get_free_instancenum"
#define VTPM_SH_ADD      "vtpm_add_and_activate"
#define VTPM_SH_RESUME   "vtpm_resume"

// This must be updated to the longest command name. Currently GETINST
#define VTPM_SH_CMD_SIZE (strlen(VTPM_SH_CMD_HDR) + strlen(VTPM_SH_CMD_FTR) + 1 + strlen(VTPM_SH_GETINST) + 2)

void handle_vtpm_mig_step2(buffer_t *in_param_buf, buffer_t *result_buf)
{
  TPM_TAG tag = VTPM_TAG_RSP;
  buffer_t out_param_buf= NULL_BUF, mig_key_buf=NULL_BUF; 
  TPM_RESULT status=TPM_SUCCESS, cmd_status;
  UINT32 out_param_size;
  
  if ( (!in_param_buf) || (!result_buf) ) {
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  // ================= Call manager and get mig key ===============
  TPMTRYRETURN( vtpm_manager_open() ); 
  TPMTRYRETURN( vtpm_manager_command(VTPM_ORD_GET_MIG_KEY,
                                     &out_param_buf, // Empty
                                     &cmd_status,
                                     &mig_key_buf) );
  
  vtpm_manager_close();

  TPMTRYRETURN(cmd_status);

  // ==================== return the  mig key =====================
  out_param_size =  VTPM_COMMAND_HEADER_SIZE + buffer_len(&mig_key_buf);

  TPMTRYRETURN( buffer_init(result_buf, 
                            out_param_size,
                            NULL) );

  BSG_PackList( result_buf->bytes, 3,
                  BSG_TPM_TAG, &tag,
                  BSG_TYPE_UINT32, &out_param_size,
                  BSG_TPM_RESULT, &status);

  memcpy(result_buf->bytes + VTPM_COMMAND_HEADER_SIZE, 
         mig_key_buf.bytes, buffer_len(&mig_key_buf));

  goto egress;

 abort_egress:
  buffer_free(result_buf);
  build_error_msg(result_buf, status);

 egress:
  return;
}

void handle_vtpm_mig_step3(buffer_t *in_param_buf, buffer_t *result_buf)
{
  TPM_TAG tag = VTPM_TAG_RSP;
  buffer_t out_param_buf= NULL_BUF, mig_key_buf=NULL_BUF, empty_buf=NULL_BUF;
  TPM_RESULT status=TPM_SUCCESS, cmd_status;
  UINT32 out_param_size, instance;
  char *shell_cmd_str=NULL;
  size_t shell_cmd_strlen;
  FILE *shell_f=NULL;

  if ( (!in_param_buf) || (!result_buf) ) {
    status = TPM_BAD_PARAMETER;
    goto abort_egress;
  }

  // ================= Read Parameters ===============
  struct pack_buf_t name_data32, state_data32;

  BSG_UnpackList(in_param_buf->bytes, 2,
                 BSG_TPM_SIZE32_DATA, &name_data32,
                 BSG_TPM_SIZE32_DATA, &state_data32);

  // Before using this string, protect us from a non-null term array.
  if (name_data32.data[name_data32.size -1] != 0x00) {
    name_data32.data[name_data32.size -1] = 0x00;
  }

  // ====== Call hotplug-script and get an instance ======
  shell_cmd_strlen = VTPM_SH_CMD_SIZE + name_data32.size + 10;
  shell_cmd_str = (char *) malloc(shell_cmd_strlen); // 10 is just padding for the UINT32

  snprintf(shell_cmd_str, shell_cmd_strlen,
	VTPM_SH_CMD_HDR VTPM_SH_GETINST VTPM_SH_CMD_FTR);

  shell_f = popen(shell_cmd_str, "r");
  fscanf(shell_f, "%d", &instance);
  pclose(shell_f);
  
  // ====== Call hotplug-script and add instance ======
  snprintf(shell_cmd_str, shell_cmd_strlen,
	VTPM_SH_CMD_HDR VTPM_SH_ADD " %s %d" VTPM_SH_CMD_FTR,
	name_data32.data, instance);
  system(shell_cmd_str);

  // ========= Call vtpm_manager and load VTPM =======
  TPMTRYRETURN( buffer_init( &out_param_buf, 
                             2*sizeof(UINT32) + state_data32.size,
                             NULL) );

  BSG_PackList(out_param_buf.bytes, 2,
                 BSG_TYPE_UINT32, &instance,
                 BSG_TPM_SIZE32_DATA, &state_data32);

  TPMTRYRETURN( vtpm_manager_open() ); 
  TPMTRYRETURN( vtpm_manager_command(VTPM_ORD_MIGRATE_IN,
                                     &out_param_buf,
                                     &cmd_status,
                                     &empty_buf) );

  vtpm_manager_close();

  TPMTRYRETURN(cmd_status);

  // ====== Call hotplug-script and resume instance ======
  snprintf(shell_cmd_str, shell_cmd_strlen,
	VTPM_SH_CMD_HDR VTPM_SH_RESUME " %d" VTPM_SH_CMD_FTR, instance);
  system(shell_cmd_str);

  goto egress;
 abort_egress:
 egress:
  free(shell_cmd_str);

  // In this case no params come back, so reuse build_error_msg even for succes.
  build_error_msg(result_buf, status);
  return;
}

