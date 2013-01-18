/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "marshal.h"
#include "log.h"
#include "vtpm_storage.h"
#include "vtpmmgr.h"
#include "tpm.h"
#include "tcg.h"

static TPM_RESULT vtpmmgr_SaveHashKey(
      const uuid_t uuid,
      tpmcmd_t* tpmcmd)
{
   TPM_RESULT status = TPM_SUCCESS;

   if(tpmcmd->req_len != VTPM_COMMAND_HEADER_SIZE + HASHKEYSZ) {
      vtpmlogerror(VTPM_LOG_VTPM, "VTPM_ORD_SAVEHASHKEY hashkey too short!\n");
      status = TPM_BAD_PARAMETER;
      goto abort_egress;
   }

   /* Do the command */
   TPMTRYRETURN(vtpm_storage_save_hashkey(uuid, tpmcmd->req + VTPM_COMMAND_HEADER_SIZE));

abort_egress:
   pack_TPM_RSP_HEADER(tpmcmd->resp,
         VTPM_TAG_RSP, VTPM_COMMAND_HEADER_SIZE, status);
   tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE;

   return status;
}

static TPM_RESULT vtpmmgr_LoadHashKey(
      const uuid_t uuid,
      tpmcmd_t* tpmcmd) {
   TPM_RESULT status = TPM_SUCCESS;

   tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE;

   TPMTRYRETURN(vtpm_storage_load_hashkey(uuid, tpmcmd->resp + VTPM_COMMAND_HEADER_SIZE));

   tpmcmd->resp_len += HASHKEYSZ;

abort_egress:
   pack_TPM_RSP_HEADER(tpmcmd->resp,
         VTPM_TAG_RSP, tpmcmd->resp_len, status);

   return status;
}


TPM_RESULT vtpmmgr_handle_cmd(
      const uuid_t uuid,
      tpmcmd_t* tpmcmd)
{
   TPM_RESULT status = TPM_SUCCESS;
   TPM_TAG tag;
   UINT32 size;
   TPM_COMMAND_CODE ord;

   unpack_TPM_RQU_HEADER(tpmcmd->req,
         &tag, &size, &ord);

   /* Handle the command now */
   switch(tag) {
      case VTPM_TAG_REQ:
         //This is a vTPM command
         switch(ord) {
            case VTPM_ORD_SAVEHASHKEY:
               return vtpmmgr_SaveHashKey(uuid, tpmcmd);
            case VTPM_ORD_LOADHASHKEY:
               return vtpmmgr_LoadHashKey(uuid, tpmcmd);
            default:
               vtpmlogerror(VTPM_LOG_VTPM, "Invalid vTPM Ordinal %" PRIu32 "\n", ord);
               status = TPM_BAD_ORDINAL;
         }
         break;
      case TPM_TAG_RQU_COMMAND:
      case TPM_TAG_RQU_AUTH1_COMMAND:
      case TPM_TAG_RQU_AUTH2_COMMAND:
         //This is a TPM passthrough command
         switch(ord) {
            case TPM_ORD_GetRandom:
               vtpmloginfo(VTPM_LOG_VTPM, "Passthrough: TPM_GetRandom\n");
               break;
            case TPM_ORD_PcrRead:
               vtpmloginfo(VTPM_LOG_VTPM, "Passthrough: TPM_PcrRead\n");
               break;
            default:
               vtpmlogerror(VTPM_LOG_VTPM, "TPM Disallowed Passthrough ord=%" PRIu32 "\n", ord);
               status = TPM_DISABLED_CMD;
               goto abort_egress;
         }

         size = TCPA_MAX_BUFFER_LENGTH;
         TPMTRYRETURN(TPM_TransmitData(tpmcmd->req, tpmcmd->req_len, tpmcmd->resp, &size));
         tpmcmd->resp_len = size;

         unpack_TPM_RESULT(tpmcmd->resp + sizeof(TPM_TAG) + sizeof(UINT32), &status);
         return status;

         break;
      default:
         vtpmlogerror(VTPM_LOG_VTPM, "Invalid tag=%" PRIu16 "\n", tag);
         status = TPM_BADTAG;
   }

abort_egress:
   tpmcmd->resp_len = VTPM_COMMAND_HEADER_SIZE;
   pack_TPM_RSP_HEADER(tpmcmd->resp,
         tag + 3, tpmcmd->resp_len, status);

   return status;
}
