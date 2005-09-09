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
// bsg.h
// 
//  This file contains API's for the TPM Byte Stream functions
//
// ==================================================================

#ifndef __BSG_H__
#define __BSG_H__

#include <stdarg.h>
#include "buffer.h"

typedef unsigned int BSG_UINT32;
typedef unsigned char BSG_BYTE;

// forward decl
struct pack_const_tuple_t;

struct pack_tuple_t;


/**
 * Byte stream generator
 */
// this has to be manually kept in sync with the
// s_fmt array!!
// but now we have a self-check function which can make sure things are well
// (if used!) 
typedef enum BSG_Type
{ 
  BSG_TYPE_FIRST = 1,
  BSG_TYPE_UINT32 = 1, // start at 1 so that Type 0 only serves as an
                       // unused/special value
  BSG_TYPE_UINT16,
  BSG_TYPE_BYTE,
  BSG_TYPE_BOOL,
  BSG_TPM_SIZE32_DATA,  // a 32 bit unsigned size, followed by
                        // a pointer to that much data. can pass a
                        // struct pack_buf_t as the param
  BSG_TPM_TAG,
  BSG_TPM_HANDLE,
  BSG_TPM_RESULT,
  BSG_TPM_RESOURCE_TYPE,
  BSG_TPM_COMMAND_CODE,
  BSG_TPM_AUTH_DATA_USAGE,
  BSG_TPM_ALGORITHM_ID,
  BSG_TPM_PROTOCOL_ID,
  BSG_TPM_KEY_USAGE,
  BSG_TPM_ENC_SCHEME,
  BSG_TPM_SIG_SCHEME,
  BSG_TPM_MIGRATE_SCHEME,
  BSG_TPM_KEY_FLAGS,
  BSG_TPM_AUTHDATA,
  BSG_TPM_SECRET,
  BSG_TPM_ENCAUTH,
  BSG_TPM_PAYLOAD_TYPE,
  
  BSG_TPM_VERSION,
  BSG_TPM_DIGEST,
  BSG_TPM_COMPOSITE_HASH,
  BSG_TPM_CHOSENID_HASH,
  BSG_TPM_NONCE,
  BSG_TPM_KEY_HANDLE,
  BSG_TPM_KEY_HANDLE_LIST,
  BSG_TPM_KEY_PARMS,
  BSG_TPM_RSA_KEY_PARMS,
  BSG_TPM_STORE_PUBKEY,
  BSG_TPM_PUBKEY,
  BSG_TPM_KEY,
  
  BSG_TPM_MIGRATIONKEYAUTH,
  BSG_TCPA_AUDIT_EVENT,
  BSG_TCPA_EVENT_CERT,
  BSG_TPM_PCR_SELECTION,
  BSG_TPM_PCR_COMPOSITE,
  BSG_TPM_PCR_INFO,
  BSG_TPM_STORED_DATA,
  BSG_TPM_SYMMETRIC_KEY,
  BSG_TPM_STORE_PRIVKEY,
  BSG_TPM_STORE_ASYMKEY,
  BSG_TPM_MIGRATE_ASYMKEY,
  BSG_TPM_QUOTE_INFO,
  BSG_TPM_IDENTITY_CONTENTS,
  BSG_TPM_PCRVALUE,
  BSG_TCPA_PCR_FLAGS,
  BSG_TCS_AUTH,
  
  // this is the BSG_TPM_KEY struct without the encData field
  BSG_TPM_KEY_NONSENSITIVE,
  
  BSG_PACKED,
  
  BSG_TYPE_MAX
} BSG_Type;

struct pack_const_tuple_t {
  BSG_Type type;
  const void * addr;
};


typedef struct pack_tuple_t {
  BSG_Type type;
  void * addr;
} pack_tuple_t;

int BSG_Pack(BSG_Type type, const void* src, BSG_BYTE* dst);
int BSG_Unpack(BSG_Type type, const BSG_BYTE* src, void* dst);
void BSG_Destroy(BSG_Type type, void* src);

// wrappers of Pack and PackList which malloc the ouput buffer. to be freed
// by the caller later. returns size of allocated buffer, or -1 in case
// allocation failed
int BSG_PackMalloc (BSG_Type type, const void* src, BSG_BYTE** o_dst);
int BSG_PackListMalloc (BSG_BYTE** outBuffer, int ParamCount, ... );

// a va_list version of PackList
int BSG_PackList(BSG_BYTE* outBuffer, int ParamCount, ... );
int BSG_UnpackList(const BSG_BYTE* inBuffer, int ParamCount, ... );
void BSG_DestroyList(int ParamCount, ... );

// wrapper of PackList which uses a buffer_t
TPM_RESULT BSG_PackListBuf (buffer_t * o_buf, int ParamCount, ...);

// and a tuple version
TPM_RESULT BSG_DestroyTuple (int numParams, pack_tuple_t params[]);

void BSG_PackConst(BSG_UINT32 val, int size, BSG_BYTE* dst);
BSG_UINT32 BSG_UnpackConst(const BSG_BYTE* src, int size);

BOOL BSG_static_selfcheck ();

#endif
