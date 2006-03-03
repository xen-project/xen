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

#include "tcg.h"
#include "tcs.h"
#include "buffer.h"
#include "crypto.h"

#define STATE_FILE    "/var/vtpm/VTPM"
#define DMI_NVM_FILE  "/var/vtpm/vtpm_dm_%d.data"
#define VTPM_BE_DEV   "/dev/vtpm"
#define VTPM_CTL_DM   0

#ifndef VTPM_MUTLI_VM
 #include <sys/types.h>
 #define GUEST_TX_FIFO "/var/vtpm/fifos/guest-to-%d.fifo"
 #define GUEST_RX_FIFO "/var/vtpm/fifos/guest-from-all.fifo"

 #define VTPM_TX_FIFO  "/var/vtpm/fifos/vtpm-to-%d.fifo"
 #define VTPM_RX_FIFO  "/var/vtpm/fifos/vtpm-from-all.fifo"

 #define BE_LISTENER_THREAD 1
 #define DMI_LISTENER_THREAD 2

 // Seconds until DMI timeout. Timeouts result in DMI being out
 // of sync, which may require a reboot of DMI and guest to recover
 // from. Don't set this to low. Also note that DMI may issue a TPM
 // call so we should expect time to process at DMI + TPM processing.
 #define DMI_TIMEOUT 90 
#endif


// ------------------------ Private Structures -----------------------
typedef struct VTPM_DMI_RESOURCE_T {
  // I/O info for Manager to talk to DMI's over FIFOs
#ifndef VTPM_MUTLI_VM
  int                   guest_tx_fh;          // open GUEST_TX_FIFO
  int                   vtpm_tx_fh;           // open VTPM_TX_FIFO
  char                  *guest_tx_fname;      // open GUEST_TX_FIFO
  char                  *vtpm_tx_fname;       // open VTPM_TX_FIFO
  
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
  TPM_DIGEST            NVM_measurement;  // Equal to the SHA1 of the blob
  TPM_DIGEST            DMI_measurement;  // Correct measurement of the owning DMI
} VTPM_DMI_RESOURCE;

typedef struct tdVTPM_GLOBALS {
  // Non-persistent data
  int                 be_fh;                  // File handle to ipc used to communicate with backend
#ifndef VTPM_MULTI_VM
  int                 vtpm_rx_fh;
  int                 guest_rx_fh;
  int                 connected_dmis;     // Used to close guest_rx when no dmis are connected
  
  pid_t               master_pid;
#endif
  struct hashtable    *dmi_map;               // Table of all DMI's known indexed by persistent instance #
#ifndef VTPM_MULTI_VM
  pthread_mutex_t     dmi_map_mutex;          // 
#endif
  TCS_CONTEXT_HANDLE  manager_tcs_handle;     // TCS Handle used by manager
  TPM_HANDLE          storageKeyHandle;       // Key used by persistent store
  CRYPTO_INFO         storageKey;             // For software encryption
  CRYPTO_INFO         bootKey;                // For saving table
  TCS_AUTH            keyAuth;                // OIAP session for storageKey 
  BOOL                DMI_table_dirty;        // Indicates that a command
                                              // has updated the DMI table

    
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

TPM_RESULT VTPM_SaveService(void);
TPM_RESULT VTPM_LoadService(void);

TPM_RESULT close_dmi( VTPM_DMI_RESOURCE *dmi_res);
#endif // __VTPMPRIV_H__
