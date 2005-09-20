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

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "tcs.h"
#include "contextmgr.h"
#include "log.h"
#include "hashtable.h"

BYTE* AddMemBlock(CONTEXT_HANDLE* pContextHandle, // in
		  int    BlockSize)  { // in
  
  BLOCK* pCurrentBlock = NULL;
  BLOCK* pBlock = NULL;
                    
  // check incoming params
  if (pContextHandle == NULL || BlockSize == 0)
    return NULL;

  // Create New Block
  pBlock = (BLOCK *)malloc(sizeof(BLOCK));
  if (pBlock == NULL)
    return (0);

  pBlock->aMemory = (BYTE *)malloc(sizeof(BYTE) * BlockSize);
  if (pBlock->aMemory == NULL)
    return (0);

  memset(pBlock->aMemory, 0, BlockSize);
  pBlock->nBlockSize = BlockSize;
  pBlock->pNextBlock = NULL;
  
  // search for the last block created where to add the 
  // newly created block
  if(pContextHandle->pTopBlock != NULL) {
    pCurrentBlock = pContextHandle->pTopBlock;
    while(pCurrentBlock->pNextBlock != NULL)
      pCurrentBlock = pCurrentBlock->pNextBlock;
    
    
    pCurrentBlock->pNextBlock= pBlock;
  } else
    pContextHandle->pTopBlock = pBlock;
  
  
  pContextHandle->nBlockCount++;
  
  return pBlock->aMemory;
}


BOOL DeleteMemBlock(CONTEXT_HANDLE* pContextHandle, // in
                    BYTE*   pTCPA_BYTEs) { // in
  BLOCK* pCurrentBlock = NULL;
  BLOCK* pParentBlock = NULL;
  BOOL bFound = FALSE;
  
  if (pContextHandle == NULL) 
    return FALSE;

  
  // Search for the Block in the context by aMemory pointer
  pParentBlock = NULL;
  pCurrentBlock = pContextHandle->pTopBlock;
  
  while(pCurrentBlock != NULL) {
    // If aMemory block is found, delete it 
    if(pCurrentBlock->aMemory == pTCPA_BYTEs || pTCPA_BYTEs == NULL) {
      // if it is the top Block, remove it from the top, 
      // otherwise remove it from the ParentBlock and stitch 
      // the NextBlock to the ParentBlock
      if(pParentBlock == NULL)
	pContextHandle->pTopBlock = pContextHandle->pTopBlock->pNextBlock;
      else
	pParentBlock->pNextBlock = pCurrentBlock->pNextBlock;
      
      // delete memory Block associated with pointer pTCPA_BYTEs
      free(pCurrentBlock->aMemory);
      pCurrentBlock->aMemory = NULL;
      
      free(pCurrentBlock);
      pCurrentBlock = pParentBlock;
      
      pContextHandle->nBlockCount--;
      bFound = TRUE;
    }
  
    if(pCurrentBlock != NULL) {
      pParentBlock = pCurrentBlock;
      pCurrentBlock = pCurrentBlock->pNextBlock;
    }
  }
  
  return bFound;
}

BOOL AddHandleToList(TCS_CONTEXT_HANDLE hContext, // in
		     TPM_RESOURCE_TYPE type, // in
		     TPM_HANDLE    handle)  { // in
  HANDLE_LIST* pNewHandle = NULL;

  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Adding Handle to list\n");
  CONTEXT_HANDLE* pContextHandle = LookupContext(hContext);

  if (pContextHandle == NULL)
    return 0;
  
  pNewHandle = (HANDLE_LIST *)malloc(sizeof(HANDLE_LIST));
  
  if (pNewHandle == NULL) 
    return (0);
  
  pNewHandle->handle = handle;
  pNewHandle->type = type;
  pNewHandle->pNextHandle = pContextHandle->pHandleList;
  
  pContextHandle->pHandleList = pNewHandle;
  
  return 1;
}

BOOL DeleteHandleFromList(   TCS_CONTEXT_HANDLE hContext, // in		     
                             TPM_HANDLE          handle) { // in
    
  CONTEXT_HANDLE* pContextHandle = LookupContext(hContext);

  HANDLE_LIST *pCurrentHandle = pContextHandle->pHandleList, 
              *pLastHandle = pCurrentHandle;
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Deleting Handle from list\n");
  
  if (pContextHandle == NULL)
    return 0;
  
  while (1) {
    
    if (pCurrentHandle->handle == handle) { // Found element
      if (pCurrentHandle == pLastHandle) { // First element in list 
	pContextHandle->pHandleList = pCurrentHandle->pNextHandle;
	free(pCurrentHandle);
      } else { // Ordinary element
	pLastHandle->pNextHandle = pCurrentHandle->pNextHandle;
	free(pCurrentHandle);
      }
      
      return 1;
      
    } else { // Not found yet;
      pLastHandle = pCurrentHandle;
      pCurrentHandle = pCurrentHandle->pNextHandle;
      if (pCurrentHandle == NULL) // Found end of list
	return 0;
    }
    
  }
}

BOOL FreeHandleList(    CONTEXT_HANDLE*     pContextHandle) { // in
  HANDLE_LIST* pCurrentHandle;
  BOOL returncode = TRUE;
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Freeing all handles for context\n");
  
  if (pContextHandle == NULL)
    return 1;
  
  pCurrentHandle = pContextHandle->pHandleList;
  while (pCurrentHandle != NULL) {
    
    switch (pCurrentHandle->type) {
    case TPM_RT_KEY:
      returncode = returncode && !TCSP_EvictKey(pContextHandle->handle, pCurrentHandle->handle);
      break;
    case TPM_RT_AUTH:
      returncode = returncode && !TCSP_TerminateHandle(pContextHandle->handle, pCurrentHandle->handle);
      break;
    default:
      returncode = FALSE;
    }
    
    pCurrentHandle = pCurrentHandle->pNextHandle;
    
  }
  
  return 1;
}
