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
// vtpm_migrator.h
// 
//  Public Interface header for VTPM Migrator 
//
// ==================================================================

#ifndef __VTPM_MIGRATOR_H__
#define __VTPM_MIGRATOR_H__

#define VTPM_MTAG_REQ 0x02c1
#define VTPM_MTAG_RSP 0x02c4

// Header sizes. 
#define VTPM_COMMAND_HEADER_SIZE ( 2 + 4 + 4)
//               sizeof(TPM_TAG + UINT32 + TPM_COMMAND_CODE)

//*********************** Connection Info **************************
#define VTPM_MIG_PORT 48879 

//************************ Command Codes ***************************
#define VTPM_MORD_MIG_STEP1     0x00
#define VTPM_MORD_MIG_STEP2     0x01
#define VTPM_MORD_MIG_STEP3     0x02
#define VTPM_MORD_MIG_STEP4     0x03

//************************ Return Codes ****************************
#define VTPM_SUCCESS               0
#define VTPM_FAIL                  1

/******************* Command Parameter API *************************

VTPM Command Format
  tpm tag: 2 bytes
  command size: 4 bytes         // Size of command including header but not DMI
  ord: 4 bytes                  // Command ordinal above
  parameters: size - 10 bytes   // Command Parameter

VTPM Response Format
  tpm tag: 2 bytes
  response_size: 4 bytes
  status: 4 bytes         
  parameters: size - 10 bytes


VTPM_Mig_Phase1:
    Unsupported: (Handled by scripts)
    
VTPM_Mig_Phase2
  Input Parameters:
    domain_name_size: 4 bytes
    domain_name : domain_name_size bytes
  Output Parameters:
    pub_exp_size: 4 bytes
    pub_exp: pub_exp_size bytes
    pub_mod_size: 4 bytes
    pub_mod: pub_mod_size bytes

VTPM_Mig_Phase3
  Input Parameters:
    vtpm_state_size: 4 bytes
    vtpm_state: vtpm_state_size bytes
  Output Parameters:
    none

VTPM_Mig_Phase4
    Unsupported: (Handled by scripts)


*********************************************************************/

#endif //_VTPM_MANAGER_H_
