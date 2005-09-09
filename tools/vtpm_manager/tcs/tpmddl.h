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
// tpmddl.c
// 
//  This file defines the TDDLI API
//
// ==================================================================

#ifndef __TPMDDL_H__
#define __TPMDDL_H__

#define TDDL_CAP_PROP_MANUFACTURER 0x0001

#define TDDL_E_FAIL 1
#define TDDL_E_SUCCESS 0
#define TDDL_SUCCESS 0

typedef unsigned int TDDL_UINT32;
typedef TDDL_UINT32 TDDL_RESULT;
typedef unsigned char TDDL_BYTE;

TDDL_RESULT TDDL_Open();
void TDDL_Close();
TDDL_RESULT TDDL_TransmitData( TDDL_BYTE* in,
			       TDDL_UINT32 insize,
			       TDDL_BYTE* out,
			       TDDL_UINT32* outsize);
TDDL_RESULT TDDL_GetStatus();
TDDL_RESULT TDDL_GetCapability( TDDL_UINT32 cap,
				TDDL_UINT32 sub,
				TDDL_BYTE* buffer,
				TDDL_UINT32* size);
TDDL_RESULT TDDL_SetCapability( TDDL_UINT32 cap,
				TDDL_UINT32 sub,
				TDDL_BYTE* buffer,
				TDDL_UINT32* size);

#endif // __TPMDDL_H__
