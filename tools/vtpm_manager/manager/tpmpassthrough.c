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
// tpmpassthrough.c
// 
//  Functions regarding passing DMI requests to HWTPM
//
// ==================================================================

#include "tcg.h"
#include "vtpm_manager.h"
#include "vtpmpriv.h"
#include "vtsp.h"
#include "log.h"

TPM_RESULT VTPM_Handle_TPM_Command( VTPM_DMI_RESOURCE *dmi,
				    buffer_t *inbuf,  
				    buffer_t *outbuf) {
  
  TPM_RESULT status = TPM_SUCCESS;
  TPM_COMMAND_CODE *ord;               
  
  ord = (TPM_COMMAND_CODE *) (inbuf->bytes + sizeof(TPM_TAG) + sizeof(UINT32));
  
  switch (*ord) {
    
    // Forbidden for DMI use
  case TPM_ORD_TakeOwnership:
  case TPM_ORD_ChangeAuthOwner:
  case TPM_ORD_DirWriteAuth:
  case TPM_ORD_DirRead:
  case TPM_ORD_AuthorizeMigrationKey:
  case TPM_ORD_CreateMaintenanceArchive:
  case TPM_ORD_LoadMaintenanceArchive:
  case TPM_ORD_KillMaintenanceFeature:
  case TPM_ORD_LoadManuMaintPub:
  case TPM_ORD_ReadManuMaintPub:
  case TPM_ORD_SelfTestFull:
  case TPM_ORD_SelfTestStartup:
  case TPM_ORD_CertifySelfTest:
  case TPM_ORD_ContinueSelfTest:
  case TPM_ORD_GetTestResult:
  case TPM_ORD_Reset:
  case TPM_ORD_OwnerClear:
  case TPM_ORD_DisableOwnerClear:
  case TPM_ORD_ForceClear:
  case TPM_ORD_DisableForceClear:
  case TPM_ORD_GetCapabilityOwner:
  case TPM_ORD_OwnerSetDisable:
  case TPM_ORD_PhysicalEnable:
  case TPM_ORD_PhysicalDisable:
  case TPM_ORD_SetOwnerInstall:
  case TPM_ORD_PhysicalSetDeactivated:
  case TPM_ORD_SetTempDeactivated:
  case TPM_ORD_CreateEndorsementKeyPair:
  case TPM_ORD_GetAuditEvent:
  case TPM_ORD_GetAuditEventSigned:
  case TPM_ORD_GetOrdinalAuditStatus:
  case TPM_ORD_SetOrdinalAuditStatus:
  case TPM_ORD_SetRedirection:
  case TPM_ORD_FieldUpgrade:
  case TSC_ORD_PhysicalPresence:
    status = TPM_DISABLED_CMD;
    goto abort_egress;
    break;
    
  } // End ORD Switch
  
  // Call TCS with command
  
  TPMTRY(TPM_IOERROR, VTSP_RawTransmit( dmi->TCSContext,inbuf, outbuf) );
  
  goto egress;
  
 abort_egress:
  vtpmloginfo(VTPM_LOG_VTPM, "TPM Command Failed in tpmpassthrough.\n");
 egress:
  
  return status;
}
