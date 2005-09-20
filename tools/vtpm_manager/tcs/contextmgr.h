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
// contextmgr.c
// 
//  This file contains the context management functions for TCS.
// 
// ==================================================================

#ifndef __CONTEXTMGR_H__
#define __CONTEXTMGR_H__

#include "tcg.h"

#define BLOCK_SIZE 300

typedef struct block {
  int nBlockSize;
  BYTE* aMemory;
  struct block* pNextBlock;
} BLOCK;

typedef struct handle_List {
  TPM_HANDLE handle;
  TPM_RESOURCE_TYPE type;
  struct handle_List* pNextHandle;
} HANDLE_LIST;

typedef struct context_handle {
  TCS_CONTEXT_HANDLE handle;
  int nBlockCount;
  BLOCK* pTopBlock;
  HANDLE_LIST* pHandleList;
} CONTEXT_HANDLE;

BYTE* AddMemBlock(  CONTEXT_HANDLE*     pContextHandle, // in
                    int                 BlockSize);  // in

BOOL DeleteMemBlock(CONTEXT_HANDLE* pContextHandle, // in
                    BYTE*           pTCPA_BYTEs); // in


BOOL AddHandleToList(   TCS_CONTEXT_HANDLE hContext, // in	
                        TPM_RESOURCE_TYPE   type, // in
                        TPM_HANDLE          handle); // in

BOOL DeleteHandleFromList(   TCS_CONTEXT_HANDLE hContext, // in	
                             TPM_HANDLE          handle); // in

BOOL FreeHandleList(    CONTEXT_HANDLE*     pContextHandle); // in

#endif //_CONTEXTMGR_H_
