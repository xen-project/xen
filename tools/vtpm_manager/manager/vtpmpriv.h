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
// vtpmpriv.h
// 
//  Structures and functions private to the manager
//
// ==================================================================

#ifndef __VTPMPRIV_H__
#define __VTPMPRIV_H__

#include "vtpm_manager.h"
#include "tcg.h"
#include "tcs.h"
#include "buffer.h"
#include "crypto.h"
#include "vtpm_ipc.h"

#define VTPM_MANAGER_GEN   2     // This is incremented when the manager's table
                                 // is changed. It's used for backwards compatability

#define STATE_FILE         "/var/vtpm/VTPM"
#define DMI_NVM_FILE       "/var/vtpm/vtpm_dm_%d.data"
#define VTPM_CTL_DM        0

// ------------------------ Private Structures -----------------------
typedef struct VTPM_DMI_RESOURCE_T {
  // I/O info for Manager to talk to DMI's and controllers
  vtpm_ipc_handle_t      *tx_vtpm_ipc_h;    // TX VTPM Results to DMI
  vtpm_ipc_handle_t      *rx_vtpm_ipc_h;    // RX VTPM Commands from DMI
  vtpm_ipc_handle_t      *tx_tpm_ipc_h;     // TX TPM Commands to DMI
  vtpm_ipc_handle_t      *rx_tpm_ipc_h;     // RX TPM Results from DMI
 
#ifndef VTPM_MULTI_VM 
  pid_t                 dmi_pid;
#endif

  // Non-persistent Information
  bool                  connected;
  UINT32                dmi_domain_id;
  TCS_CONTEXT_HANDLE    TCSContext;     // TCS Handle
  char                  *NVMLocation;   // NULL term string indicating location
                                        // of NVM.
  // Persistent Information about DMI
  UINT32                dmi_id;
  BYTE                  dmi_type;
  TPM_DIGEST            NVM_measurement;  // Equal to the SHA1 of the blob
  TPM_DIGEST            DMI_measurement;  // Correct measurement of the owning DMI
} VTPM_DMI_RESOURCE;

typedef struct tdVTPM_MIGKEY_LIST {
  UINT32                name_size;
  BYTE                  *name; // Name of destination (IP addr, domain name, etc)
  CRYPTO_INFO           key;
  struct tdVTPM_MIGKEY_LIST *next;
} VTPM_MIGKEY_LIST;


typedef struct tdVTPM_GLOBALS {
  // Non-persistent data
#ifndef VTPM_MULTI_VM
  pid_t               master_pid;
#endif

  int                 connected_dmis;     // To close guest_rx when no dmis are connected

  struct hashtable    *dmi_map;               // Table of all DMI's known indexed by persistent instance #
  VTPM_MIGKEY_LIST    *mig_keys;              // Table of migration keys
                      // Currently keys are loaded at migration time,
                      // TODO: Make VTPM man store a keys persistently
                      //       and update script to check if key is needed
                      //       before fetching it.

  TCS_CONTEXT_HANDLE  manager_tcs_handle;     // TCS Handle used by manager
  TPM_HANDLE          storageKeyHandle;       // Key used by persistent store
  CRYPTO_INFO         storageKey;             // For software encryption
  CRYPTO_INFO         bootKey;                // For saving table
  TCS_AUTH            keyAuth;                // OIAP session for storageKey 
    
  // Persistent Data
  TPM_AUTHDATA        owner_usage_auth;       // OwnerAuth of real TPM
  buffer_t            storageKeyWrap;         // Wrapped copy of storageKey
  TPM_AUTHDATA        srk_usage_auth;
  TPM_AUTHDATA        storage_key_usage_auth; 

  buffer_t            bootKeyWrap;            // Wrapped copy of boot key 

}VTPM_GLOBALS;

// --------------------------- Global Values --------------------------
extern VTPM_GLOBALS *vtpm_globals;   // Key info and DMI states
extern const TPM_AUTHDATA SRK_AUTH;  // SRK Well Known Auth Value

// ********************** VTPM Functions *************************
TPM_RESULT VTPM_Init_Manager(); // Start VTPM Service
void VTPM_Stop_Manager();  // Stop VTPM Service
TPM_RESULT VTPM_Manager_Handler(vtpm_ipc_handle_t *tx_ipc_h,
                                vtpm_ipc_handle_t *rx_ipc_h,
                                BOOL fw_tpm,   // Should forward TPM cmds
                                vtpm_ipc_handle_t *fw_tx_ipc_h,
                                vtpm_ipc_handle_t *fw_rx_ipc_h,
                                BOOL is_priv,
                                char *client_name);

// ********************** Command Handler Prototypes ***********************

TPM_RESULT VTPM_Handle_Load_NVM(       VTPM_DMI_RESOURCE *myDMI, 
                                        const buffer_t *inbuf, 
                                        buffer_t *outbuf);

TPM_RESULT VTPM_Handle_Save_NVM(       VTPM_DMI_RESOURCE *myDMI, 
                                        const buffer_t *inbuf, 
                                        buffer_t *outbuf);

TPM_RESULT VTPM_Handle_TPM_Command(    VTPM_DMI_RESOURCE *dmi, 
                                        buffer_t *inbuf, 
                                        buffer_t *outbuf);

TPM_RESULT VTPM_Handle_New_DMI(const buffer_t *param_buf);
                                
TPM_RESULT VTPM_Handle_Close_DMI(const buffer_t *param_buf);
                                   
TPM_RESULT VTPM_Handle_Delete_DMI(const buffer_t *param_buf);

TPM_RESULT VTPM_Handle_Migrate_In( const buffer_t *param_buf,
                                   buffer_t *result_buf);

TPM_RESULT VTPM_Handle_Migrate_Out ( const buffer_t *param_buf,
                                     buffer_t *result_buf);

TPM_RESULT VTPM_Handle_Get_Migration_key( const buffer_t *param_buf,
                                          buffer_t *result_buf);

TPM_RESULT VTPM_SaveManagerData(void);
TPM_RESULT VTPM_LoadManagerData(void);

TPM_RESULT VTPM_New_DMI_Extra(VTPM_DMI_RESOURCE *dmi_res, BYTE vm_type, BYTE startup_mode);

TPM_RESULT VTPM_Close_DMI_Extra(VTPM_DMI_RESOURCE *dmi_res);

// Helper functions
TPM_RESULT close_dmi(VTPM_DMI_RESOURCE *dmi_res);
TPM_RESULT init_dmi(UINT32 dmi_id, BYTE type,  VTPM_DMI_RESOURCE **dmi_res);

TPM_RESULT envelope_encrypt(const buffer_t     *inbuf,
                             CRYPTO_INFO        *asymkey,
                             buffer_t           *sealed_data);

TPM_RESULT envelope_decrypt(const buffer_t     *cipher,
                            TCS_CONTEXT_HANDLE TCSContext,
                            TPM_HANDLE         keyHandle,
                            const TPM_AUTHDATA *key_usage_auth,
                            buffer_t           *unsealed_data);

#endif // __VTPMPRIV_H__
