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
// vtpm_manager.h
// 
//  Public Interface header for VTPM Manager
//
// ==================================================================

#ifndef __VTPM_MANAGER_H__
#define __VTPM_MANAGER_H__

#define VTPM_TAG_REQ 0x01c1
#define VTPM_TAG_RSP 0x01c4
#define COMMAND_BUFFER_SIZE 4096

// Header sizes. Note Header MAY include the DMI
#define VTPM_COMMAND_HEADER_SIZE_CLT ( 2 + 4 + 4)
//                    sizeof(TPM_TAG + UINT32 + TPM_COMMAND_CODE)
#define VTPM_COMMAND_HEADER_SIZE_SRV ( 4 + VTPM_COMMAND_HEADER_SIZE_CLT )
//                    sizeof( UINT32 + VTPM_COMMAND_HEADER_SIZE_CLT)

//************************ Command Codes ****************************
#define VTPM_ORD_BASE       0x0000
#define VTPM_PRIV_MASK      0x01000000 // Priviledged VTPM Command
#define VTPM_PRIV_BASE      (VTPM_ORD_BASE | VTPM_PRIV_MASK)

// Non-priviledged VTPM Commands (From DMI's)
#define VTPM_ORD_SAVENVM      (VTPM_ORD_BASE + 1) // DMI Saves Secrets
#define VTPM_ORD_LOADNVM      (VTPM_ORD_BASE + 2) // DMI Loads Secrets
#define VTPM_ORD_TPMCOMMAND   (VTPM_ORD_BASE + 3) // DMI issues HW TPM Command
#define VTPM_ORD_GET_MIG_KEY  (VTPM_ORD_BASE + 4) // Get manager's migration key
#define VTPM_ORD_LOAD_MIG_KEY (VTPM_ORD_BASE + 5) // load dest migration key 

// Priviledged VTPM Commands (From management console)
#define VTPM_ORD_OPEN         (VTPM_PRIV_BASE + 1) // Creates/reopens DMI
#define VTPM_ORD_CLOSE        (VTPM_PRIV_BASE + 2) // Closes a DMI
#define VTPM_ORD_DELETE       (VTPM_PRIV_BASE + 3) // Permemently Deletes DMI
#define VTPM_ORD_MIGRATE_IN   (VTPM_PRIV_BASE + 4) // Load migrated VTPM
#define VTPM_ORD_MIGRATE_OUT  (VTPM_PRIV_BASE + 5) // migrate VTPM to dest 

//************************ Return Codes ****************************
#define VTPM_TYPE_PVM 1 // Paravirtualized Domain
#define VTPM_TYPE_HVM 2 // HVM Domain

//************************ Return Codes ****************************
#define VTPM_SUCCESS               0
#define VTPM_FAIL                  1
#define VTPM_UNSUPPORTED           2
#define VTPM_FORBIDDEN             3
#define VTPM_RESTORE_CONTEXT_FAILED    4
#define VTPM_INVALID_REQUEST       5

//*********************** Parameter Values *************************
#define VTPM_TYPE_NON_MIGRATABLE  0x00
#define VTPM_TYPE_MIGRATABLE      0x01
#define VTPM_TYPE_MIGRATED        0xFF // VTPM has been migrated.
                                       // VTPM can be recovered or deleted only

/******************* Command Parameter API *************************

VTPM Command Format
  dmi: 4 bytes                  // Source of message. 
                                // WARNING: This is prepended by the channel. 
                                // Thus it is received by VTPM Manager, 
                                // but not sent by DMI
  tpm tag: 2 bytes
  command size: 4 bytes         // Size of command including header but not DMI
  ord: 4 bytes                  // Command ordinal above
  parameters: size - 10 bytes   // Command Parameter

VTPM Response Format
  tpm tag: 2 bytes
  response_size: 4 bytes
  status: 4 bytes         
  parameters: size - 10 bytes


VTPM_Open:
  Input Parameters:
    mig_type: 1 byte 
    startup_mode: 1 byte // Cold Boot = 1, resume = 2, deactive = 3
    domain type: 1 byte
    instance_id: 4 bytes
  Output Parameters:
    None
    
VTPM_Close
  Input Parameters:
    instance_id: 4 bytes
  Output Parameters:
    None

VTPM_Delete
  Input Parameters:
    instance_id: 4 bytes
  Output Parameters:
    None

VTPM_SaveNVM
  Input Parameters:
    data: n bytes (Header indicates size of data)
  Output Parameters:
    None

VTPM_LoadNVM
  Input Parameters:
    None
  Output Parameters:
    data: n bytes (Header indicates size of data)

VTPM_TPMCommand
  Input Parameters:
    TPM Command Byte Stream: n bytes 
  Output Parameters:
    TPM Reponse Byte Stream: n bytes 

*********************************************************************/

#endif //_VTPM_MANAGER_H_
