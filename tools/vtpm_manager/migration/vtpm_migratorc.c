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

#include <stdio.h>
#include <string.h>

#include "tcg.h"
#include "log.h"
#include "bsg.h"
#include "buffer.h"
#include "vtpm_migrator.h"
#include "vtpm_manager.h"

TPM_RESULT handle_vtpm_mig_step2(char *server_addr, 
                                 char *name, 
                                 UINT32 instance) {
  TPM_RESULT status, cmd_status;
  buffer_t out_param_buf=NULL_BUF, mig_key_buf=NULL_BUF, empty_buf=NULL_BUF;
  UINT32 offset; 
  struct pack_buf_t addr_data32;

  //===== Get Destination's Public Migration Key ======
  TPMTRYRETURN( vtpm_migratord_open(server_addr) );

  TPMTRYRETURN( vtpm_migratord_command(VTPM_MORD_MIG_STEP2,
                                     &out_param_buf,
                                     &cmd_status, 
                                     &mig_key_buf) ); 
  vtpm_migratord_close();

  TPMTRYRETURN(cmd_status);

  //===== Load migration key into vtpm_manager ========

  addr_data32.data = (BYTE *)server_addr;
  addr_data32.size = strlen(server_addr) + 1; // Include the null

  TPMTRYRETURN ( buffer_init ( &out_param_buf, 
                               sizeof(UINT32) + addr_data32.size +buffer_len(&mig_key_buf),
                               NULL ) ) ;

  offset =  BSG_PackList(out_param_buf.bytes, 1,
               BSG_TPM_SIZE32_DATA, &addr_data32);

  memcpy(out_param_buf.bytes + offset , mig_key_buf.bytes, buffer_len(&mig_key_buf) );

  TPMTRYRETURN ( vtpm_manager_open() );

  TPMTRYRETURN ( vtpm_manager_command(VTPM_ORD_LOAD_MIG_KEY,
                                      &out_param_buf,
                                      &cmd_status,
                                      &empty_buf) );

  vtpm_manager_close();

  TPMTRYRETURN(cmd_status);

  goto egress;

 abort_egress:
 egress:

  buffer_free(&mig_key_buf);
  buffer_free(&out_param_buf);

  return status;
}


TPM_RESULT handle_vtpm_mig_step3(char *server_addr, 
                                 char *name, 
                                 UINT32 instance) {
  TPM_RESULT status, cmd_status;
  buffer_t out_param_buf=NULL_BUF, state_buf=NULL_BUF, empty_buf=NULL_BUF;
  struct pack_buf_t addr_data32, name_data32, state_data32;

  //===== Get vtpm state from vtpm_manager ========
  addr_data32.data = (BYTE *)server_addr;
  addr_data32.size = strlen(server_addr) + 1; // Include the null

  TPMTRYRETURN ( buffer_init ( &out_param_buf,
                               (2 * sizeof(UINT32)) + addr_data32.size,
                               NULL ) ) ;

  BSG_PackList(out_param_buf.bytes, 2,
                 BSG_TYPE_UINT32, &instance, 
                 BSG_TPM_SIZE32_DATA, &addr_data32);

  TPMTRYRETURN ( vtpm_manager_open() );

  TPMTRYRETURN ( vtpm_manager_command(VTPM_ORD_MIGRATE_OUT,
                                      &out_param_buf,
                                      &cmd_status,
                                      &state_buf) );

  vtpm_manager_close();

  TPMTRYRETURN(cmd_status);

  TPMTRYRETURN( buffer_free( &out_param_buf ) );

  //===== Send vtpm state to destination ======
  name_data32.data = (BYTE *)name;
  name_data32.size = strlen(name) + 1; // Include the null
  state_data32.data = state_buf.bytes;
  state_data32.size = buffer_len(&state_buf);

  TPMTRYRETURN( buffer_init( &out_param_buf,
                             2 * sizeof(UINT32) + name_data32.size + state_data32.size,
                             NULL ) ) ;
                             
  BSG_PackList(out_param_buf.bytes, 2,
                 BSG_TPM_SIZE32_DATA, &name_data32,
                 BSG_TPM_SIZE32_DATA, &state_data32);

  TPMTRYRETURN( vtpm_migratord_open(server_addr) );

  TPMTRYRETURN( vtpm_migratord_command(VTPM_MORD_MIG_STEP3,
                                     &out_param_buf,
                                     &cmd_status, 
                                     &empty_buf) ); 
  vtpm_migratord_close();

  TPMTRYRETURN(cmd_status);

  goto egress;

 abort_egress:
 egress:

  buffer_free( &out_param_buf);
  buffer_free( &state_buf);
  buffer_free( &empty_buf);

  return status;
}


// Usage vtpm_migrator addr domain_name instance step

int main(int argc, char **argv) {

    /* variables for processing of command */
    TPM_RESULT status = TPM_FAIL;
    char *server_addr, *name;
    UINT32 instance, step;

    if (argc != 5) {
      vtpmlogerror(VTPM_LOG_VTPM, "Usage: vtpm_migrator addr vm_name instance step\n");
      vtpmlogerror(VTPM_LOG_VTPM, "       params given %d\n", argc);
      status= TPM_BAD_PARAMETER;
      goto abort_egress;
    }

    server_addr = argv[1];
    name = argv[2];
    instance = atoi( argv[3] );
    step = atoi( argv[4] );    

    switch (step) {
    case VTPM_MORD_MIG_STEP2:
      status = handle_vtpm_mig_step2(server_addr, name, instance);
      break;
 
    case VTPM_MORD_MIG_STEP3:
      status = handle_vtpm_mig_step3(server_addr, name, instance);
      break;

    default:
      status = TPM_BAD_PARAMETER;
      goto abort_egress;
      break;
    }
 
    goto egress;
 abort_egress:
 egress:

    return status;
}

