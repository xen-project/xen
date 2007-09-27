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
// tcs.c
// 
//  This file contains the functions that implement a TCS.
// 
// ==================================================================

#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "tcg.h"
#include "bsg.h"
#include "tcs.h"
#include "contextmgr.h"
#include "tpmddl.h"
#include "log.h"
#include "hashtable.h"
#include "hashtable_itr.h"

// Static Global Vars for the TCS
static int TCS_m_nCount = 0;

#define TCPA_MAX_BUFFER_LENGTH 0x2000

static BYTE InBuf [TCPA_MAX_BUFFER_LENGTH];
static BYTE OutBuf[TCPA_MAX_BUFFER_LENGTH];

struct hashtable *context_ht;

// -------------------------- Hash table functions --------------------

static unsigned int hashfunc32(void *ky) {
  return (* (UINT32 *) ky);
}

static int equals32(void *k1, void *k2) {
  return (*(UINT32 *) k1 == *(UINT32 *) k2);
}

CONTEXT_HANDLE *LookupContext( TCS_CONTEXT_HANDLE  hContext) {
  return( (CONTEXT_HANDLE *) hashtable_search(context_ht, &hContext) );
}

// ---------------------------------------------------------------------------------
// Initialization/Uninitialization SubComponent API
// ---------------------------------------------------------------------------------
TPM_RESULT TCS_create() {
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TPM_RESULT result = TPM_FAIL;
  
  if (TCS_m_nCount == 0) {
    vtpmloginfo(VTPM_LOG_TCS, "Constructing new TCS:\n");
    hRes = TDDL_Open();

    context_ht = create_hashtable(10, hashfunc32, equals32);
	  
    if ((hRes == TDDL_SUCCESS) && (context_ht != NULL)) {
      result = TPM_SUCCESS;
      TCS_m_nCount++;
    } else {
      result = TPM_IOERROR;
      hashtable_destroy(context_ht, 1);
    }
  } else
    TCS_m_nCount++;
    
  return(result);
}


void TCS_destroy()
{
  TCS_m_nCount--;
  
  if (TCS_m_nCount == 0) {
    vtpmloginfo(VTPM_LOG_TCS, "Destructing TCS:\n");
    TDDL_Close();

    struct hashtable_itr *context_itr;
    TCS_CONTEXT_HANDLE  *hContext;
    
    // Close all the TCS contexts. TCS should evict keys based on this
    if (hashtable_count(context_ht) > 0) {
      context_itr = hashtable_iterator(context_ht);
      do {
        hContext = (TCS_CONTEXT_HANDLE *) hashtable_iterator_key(context_itr);
	if (TCS_CloseContext(*hContext) != TPM_SUCCESS) 
	    vtpmlogerror(VTPM_LOG_TCS, "Failed to close context %d properly.\n", *hContext);
      
      } while (hashtable_iterator_advance(context_itr));
      free(context_itr);
    }
    hashtable_destroy(context_ht, 1);
  }
  
}

TPM_RESULT TCS_Malloc(  TCS_CONTEXT_HANDLE  hContext, // in
                        UINT32              MemSize, // in
                        BYTE**              ppMemPtr) {// out

  TPM_RESULT returnCode = TPM_FAIL;
  CONTEXT_HANDLE* pContextHandle = LookupContext(hContext);
  
  if (pContextHandle != NULL && ppMemPtr != NULL) {
    *ppMemPtr = (BYTE *)AddMemBlock(pContextHandle, MemSize);
    returnCode = TPM_SUCCESS;
  }
  
  return returnCode;
}

TPM_RESULT TCS_FreeMemory(  TCS_CONTEXT_HANDLE  hContext, // in
                            BYTE*               pMemory) { // in
  TPM_RESULT returnCode = TPM_FAIL;
  CONTEXT_HANDLE* pContextHandle = LookupContext(hContext);
  
  if ( (pContextHandle != NULL && pMemory != NULL) &&
       (DeleteMemBlock(pContextHandle, pMemory) == TRUE) )
    returnCode = TPM_SUCCESS;
 
  
  return returnCode;
}

TPM_RESULT TCS_OpenContext(TCS_CONTEXT_HANDLE* hContext) { // out
  TPM_RESULT returnCode = TPM_FAIL;
  TCS_CONTEXT_HANDLE *newContext;
  
  vtpmloginfo(VTPM_LOG_TCS, "Calling TCS_OpenContext:\n");
  
  if (hContext) {
    CONTEXT_HANDLE* pContextHandle = (CONTEXT_HANDLE *) malloc(sizeof(CONTEXT_HANDLE));
    if (pContextHandle == NULL) 
      return TPM_SIZE;
    
    // initialize to 0
    pContextHandle->nBlockCount = 0;
    pContextHandle->pTopBlock = NULL;
    pContextHandle->pHandleList = NULL;
    
    // Create New Block
    AddMemBlock(pContextHandle, BLOCK_SIZE);
    
    newContext = (TCS_CONTEXT_HANDLE *) malloc(sizeof(TCS_CONTEXT_HANDLE));
    *newContext = (TCS_CONTEXT_HANDLE) (((uintptr_t) pContextHandle >> 2) & 0xffffffff);
    
    if (hashtable_search(context_ht, &newContext) !=NULL)
    	*newContext += 1;
    
    pContextHandle->handle = *newContext;
    if (!hashtable_insert(context_ht, newContext, pContextHandle)) {
        free(newContext);
        free(pContextHandle);
    	returnCode = TPM_FAIL;
    } else {
    	*hContext = *newContext;
    	returnCode = TPM_SUCCESS;
    }
  }
  
  return(returnCode);
}

TPM_RESULT TCS_CloseContext(TCS_CONTEXT_HANDLE hContext) {// in
  //FIXME: TCS SHOULD Track failed auths and make sure
  //we don't try and re-free them here.
  TPM_RESULT returnCode = TPM_FAIL;
  
  CONTEXT_HANDLE* pContextHandle = LookupContext(hContext);
  
  if(pContextHandle != NULL) {
    // Print test info
    vtpmloginfo(VTPM_LOG_TCS, "Calling TCS_CloseContext.\n");
      
    // free memory for all the blocks
    DeleteMemBlock(pContextHandle, NULL );      
    pContextHandle->pTopBlock = NULL;
    
    FreeHandleList(pContextHandle);
    if (pContextHandle->pHandleList != NULL) 
      vtpmlogerror(VTPM_LOG_TCS, "Not all handles evicted from TPM.\n");
    
    // Release the TPM's resources
    if (hashtable_remove(context_ht, &hContext) == NULL) 
      vtpmlogerror(VTPM_LOG_TCS, "Not all handles evicted from TPM.\n");
    
    free(pContextHandle);
    returnCode = TPM_SUCCESS;
  }
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Finished closing context\n");
  return(returnCode);
}

// ------------------------------------------------------------------
// Internal Functions
// ------------------------------------------------------------------
int packAuth(BYTE* dst, TCS_AUTH* auth) {
  // CHECK: according to the command specs, the outgoing auth params are:
  // nonceEven
  // nonceOdd
  // continueAuthSession
  // auth digest for return params
  //
  // this is a bit different than this code...
  
  return BSG_PackList(dst, 4, 
		      BSG_TYPE_UINT32, &(auth->AuthHandle), 
		      BSG_TPM_NONCE, &(auth->NonceOdd), 
		      BSG_TYPE_BOOL, &(auth->fContinueAuthSession), 
		      BSG_TPM_AUTHDATA, &(auth->HMAC));
}

int unpackAuth(TCS_AUTH* auth, BYTE* src) {
  return BSG_UnpackList(src, 3, 
			BSG_TPM_NONCE, &(auth->NonceEven), 
			BSG_TYPE_BOOL, &(auth->fContinueAuthSession), 
			BSG_TPM_AUTHDATA, &(auth->HMAC));
}

// ------------------------------------------------------------------
// Authorization Commands
// ------------------------------------------------------------------

TPM_RESULT TCSP_OIAP(TCS_CONTEXT_HANDLE hContext, // in
		     TCS_AUTHHANDLE*  authHandle, // out 
		     TPM_NONCE*   nonce0)  // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  TPM_COMMAND_CODE ordinal = TPM_ORD_OIAP;
  UINT32 paramSize = 0;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (authHandle == NULL || nonce0 == NULL) 
    return TPM_BAD_PARAMETER;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 3, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal);
    
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
      == TDDL_SUCCESS) {
    
    // unpack to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList( OutBuf, 3, 
			    BSG_TPM_TAG, &tag, 
			    BSG_TYPE_UINT32, &paramSize, 
			    BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      // Extract the remaining output parameters
      BSG_UnpackList(OutBuf+i, 2, 
		     BSG_TYPE_UINT32, authHandle, 
		     BSG_TPM_NONCE, nonce0);
      
      if (!AddHandleToList(hContext, TPM_RT_AUTH, *authHandle)) 
        vtpmlogerror(VTPM_LOG_TCS, "New AuthHandle not recorded\n");
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "Failed with return code %s\n", tpm_get_error_name(returnCode));
    
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_OSAP(TCS_CONTEXT_HANDLE hContext,  // in
		     TPM_ENTITY_TYPE  entityType,  // in
		     UINT32    entityValue, // in
		     TPM_NONCE   nonceOddOSAP, // in
		     TCS_AUTHHANDLE*  authHandle,  // out 
		     TPM_NONCE*   nonceEven,  // out
		     TPM_NONCE*   nonceEvenOSAP) // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_OSAP;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (authHandle == NULL || nonceEven == NULL || nonceEvenOSAP == NULL)
    return TPM_BAD_PARAMETER;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 6, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT16, &entityType, 
			  BSG_TYPE_UINT32, &entityValue, 
			  BSG_TPM_NONCE, &nonceOddOSAP);
  
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
            == TDDL_SUCCESS) {

    // unpack to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      // Extract the remaining output parameters
      BSG_UnpackList(OutBuf+i, 3, 
		     BSG_TYPE_UINT32, authHandle, 
		     BSG_TPM_NONCE, nonceEven, 
		     BSG_TPM_NONCE, nonceEvenOSAP);
      
      if (!AddHandleToList(hContext, TPM_RT_AUTH, *authHandle)) {
	    vtpmlogerror(VTPM_LOG_TCS, "New AuthHandle not recorded\n");
      }
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "Failed with return code %s\n", tpm_get_error_name(returnCode));
    
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_TakeOwnership(TCS_CONTEXT_HANDLE hContext,   // in
			      UINT16    protocolID,   // in
			      UINT32    encOwnerAuthSize, // in 
			      BYTE*    encOwnerAuth,  // in
			      UINT32    encSrkAuthSize,  // in
			      BYTE*    encSrkAuth,   // in
			      UINT32*    SrkSize,   // in, out
			      BYTE**    Srk,    // in, out
			      TCS_AUTH*   ownerAuth)   // in, out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_TakeOwnership;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32 InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32 OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (encOwnerAuth == NULL || encSrkAuth == NULL || SrkSize == NULL || *Srk == NULL) 
    return TPM_BAD_PARAMETER;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 5, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT16, &protocolID, 
			  BSG_TYPE_UINT32, &encOwnerAuthSize);
  
  memcpy(InBuf+InLength, encOwnerAuth, encOwnerAuthSize);
  InLength += encOwnerAuthSize;
  InLength += BSG_Pack(   BSG_TYPE_UINT32, 
			  &encSrkAuthSize, 
			  InBuf+InLength);
  memcpy(InBuf+InLength, encSrkAuth, encSrkAuthSize);
  InLength += encSrkAuthSize;
  memcpy(InBuf+InLength, *Srk, *SrkSize);
  InLength += *SrkSize;
  InLength += packAuth(InBuf+InLength, ownerAuth);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, 
	   &InLength, 
	   InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
              == TDDL_SUCCESS){
    
    // unpack to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList( OutBuf, 3, 
			    BSG_TPM_TAG, &tag, 
			    BSG_TYPE_UINT32, &paramSize, 
			    BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH1_COMMAND) {
      // Extract the remaining output parameters
      TPM_KEY srkPub;
      i += BSG_Unpack(BSG_TPM_KEY,  OutBuf+i,  &srkPub); 
      unpackAuth(ownerAuth, OutBuf+i);
      
      // fill output params
      BYTE tempBuf[1024];
      *SrkSize = BSG_Pack(BSG_TPM_KEY,  &srkPub, tempBuf);
      if (TCS_Malloc(hContext, *SrkSize, Srk) == TPM_FAIL) {
	return(TPM_SIZE);
      }
      memcpy(*Srk, tempBuf, *SrkSize);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_TakeOwnership Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}


TPM_RESULT TCSP_DisablePubekRead (  TCS_CONTEXT_HANDLE hContext, // in
                                    TCS_AUTH*   ownerAuth) { // in, out
 
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_DisablePubekRead;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32 InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32 OutLength = TCPA_MAX_BUFFER_LENGTH;
    
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 3, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal);
  
  InLength += packAuth(InBuf+InLength, ownerAuth);
 
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
              == TDDL_SUCCESS){
    
    // unpack to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList( OutBuf, 3, 
			    BSG_TPM_TAG, &tag, 
			    BSG_TYPE_UINT32, &paramSize, 
			    BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH1_COMMAND) {
      // Extract the remaining output parameters
      unpackAuth(ownerAuth, OutBuf+i);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_DisablePubekRead Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}


TPM_RESULT TCSP_TerminateHandle(TCS_CONTEXT_HANDLE hContext, // in
                                TCS_AUTHHANDLE  handle)  // in
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_Terminate_Handle;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 4, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &handle);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
              == TDDL_SUCCESS) {
    
    // unpack to get the tag, paramSize, & returnCode
    BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (!DeleteHandleFromList(hContext, handle)) 
      vtpmlogerror(VTPM_LOG_TCS, "KeyHandle not removed from list\n");
       
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      // Print debug info
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_TerminateHandle Failed with return code %s\n", tpm_get_error_name(returnCode));
    
  }
  
  return(returnCode);
}

// TPM Mandatory
TPM_RESULT TCSP_Extend( TCS_CONTEXT_HANDLE hContext, // in
                        TPM_PCRINDEX  pcrNum,  // in
                        TPM_DIGEST  inDigest, // in
                        TPM_PCRVALUE*  outDigest) // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_Extend;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 5, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &pcrNum, 
			  BSG_TPM_DIGEST, &inDigest);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
              == TDDL_SUCCESS) {
    
    // unpack to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND){
      // Extract the remaining output parameters
      BSG_Unpack(BSG_TPM_PCRVALUE, OutBuf+i, outDigest);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_Extend Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_Seal(   TCS_CONTEXT_HANDLE hContext,  // in
                        TCS_KEY_HANDLE  keyHandle,  // in
                        TPM_ENCAUTH   encAuth,  // in
                        UINT32    pcrInfoSize, // in
                        BYTE*    PcrInfo,  // in
                        UINT32    inDataSize,  // in
                        BYTE*    inData,   // in
                        TCS_AUTH*   pubAuth,  // in, out
                        UINT32*    SealedDataSize, // out
                        BYTE**    SealedData)  // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_Seal;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (inData == NULL || pubAuth == NULL || SealedDataSize == NULL || SealedData == NULL)
    return TPM_BAD_PARAMETER;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 6, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &keyHandle, 
			  BSG_TPM_ENCAUTH, encAuth, 
			  BSG_TYPE_UINT32, &pcrInfoSize);
  memcpy(InBuf+InLength, PcrInfo, pcrInfoSize);
  InLength += pcrInfoSize;
  InLength += BSG_Pack(BSG_TYPE_UINT32, &inDataSize, InBuf+InLength);
  memcpy(InBuf+InLength, inData, inDataSize);
  InLength += inDataSize;
  InLength += packAuth(InBuf+InLength, pubAuth);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
    
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) 
              == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH1_COMMAND) {
      // Extract the remaining output parameters
      TPM_STORED_DATA sealedData;
      
      i += BSG_Unpack(BSG_TPM_STORED_DATA, OutBuf+i, &sealedData); 
      unpackAuth(pubAuth, OutBuf+i);
      
      // fill SealedData
      BYTE tempBuf[1024];
      *SealedDataSize = BSG_Pack(BSG_TPM_STORED_DATA, &sealedData, tempBuf);
      if (TCS_Malloc(hContext, *SealedDataSize, SealedData) == TPM_FAIL) {
	return TPM_SIZE;
      }
      memcpy(*SealedData, tempBuf, *SealedDataSize);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_Seal Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_Unseal(TCS_CONTEXT_HANDLE hContext,  // in
		       TCS_KEY_HANDLE  parentHandle, // in
		       UINT32    SealedDataSize, // in
		       BYTE*    SealedData,  // in
		       TCS_AUTH*   parentAuth,  // in, out
		       TCS_AUTH*   dataAuth,  // in, out
		       UINT32*   DataSize,  // out
		       BYTE**    Data)   // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH2_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_Unseal;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32 InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32 OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (SealedData == NULL || parentAuth == NULL || dataAuth == NULL || 
      DataSize == NULL || Data == NULL) 
    return TPM_BAD_PARAMETER;
  
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 4, 
			              BSG_TPM_TAG, &tag, 
                          BSG_TYPE_UINT32, &paramSize, 
                          BSG_TPM_COMMAND_CODE, &ordinal, 
                          BSG_TYPE_UINT32, &parentHandle);
  memcpy(InBuf+InLength, SealedData, SealedDataSize);
  InLength += SealedDataSize;
  InLength += packAuth(InBuf+InLength, parentAuth);
  InLength += packAuth(InBuf+InLength, dataAuth);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
    
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList( OutBuf, 3, 
                            BSG_TPM_TAG, &tag, 
                            BSG_TYPE_UINT32, &paramSize, 
                            BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH2_COMMAND) {
      // Extract the remaining output parameters
      i += BSG_Unpack(BSG_TYPE_UINT32, OutBuf+i, DataSize);
      if (TCS_Malloc(hContext, *DataSize, Data) == TPM_FAIL) {
        return TPM_SIZE;
      }
      memcpy(*Data, OutBuf+i, *DataSize);
      i += *DataSize;
      i += unpackAuth(parentAuth, OutBuf+i);
      unpackAuth(dataAuth, OutBuf+i);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_Unseal Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_UnBind(TCS_CONTEXT_HANDLE hContext,  // in
		       TCS_KEY_HANDLE  keyHandle,  // in
		       UINT32    inDataSize,  // in
		       BYTE*    inData,   // in
		       TCS_AUTH*   privAuth,  // in, out
		       UINT32*   outDataSize, // out
		       BYTE**    outData)  // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_UnBind;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (inData == NULL || privAuth == NULL || outDataSize == NULL || outData == NULL)
    return TPM_BAD_PARAMETER;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 5, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &keyHandle, 
			  BSG_TYPE_UINT32, &inDataSize);
  memcpy(InBuf+InLength, inData, inDataSize);
  InLength += inDataSize;
  InLength += packAuth(InBuf+InLength, privAuth);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "\n\tSending paramSize = %d", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH1_COMMAND) {
      // Extract the remaining output parameters
      i += BSG_Unpack(BSG_TYPE_UINT32, OutBuf+i, outDataSize);
      if (TCS_Malloc(hContext, *outDataSize, outData) == TPM_FAIL)
        return TPM_SIZE;
    
      memcpy(*outData, OutBuf+i, *outDataSize);
      i += *outDataSize;
      unpackAuth(privAuth, OutBuf+i);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_UnBind Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_CreateWrapKey(TCS_CONTEXT_HANDLE hContext,   // in
			      TCS_KEY_HANDLE  hWrappingKey,  // in
			      TPM_ENCAUTH  KeyUsageAuth,  // in
			      TPM_ENCAUTH  KeyMigrationAuth, // in
			      UINT32*    pcKeySize,   // in, out
			      BYTE**    prgbKey,   // in, out
			      TCS_AUTH*   pAuth)    // in, out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_CreateWrapKey;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (pcKeySize == NULL || *prgbKey == NULL || pAuth == NULL)
    return TPM_BAD_PARAMETER;
  
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 6, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &hWrappingKey, 
			  BSG_TPM_ENCAUTH, KeyUsageAuth, 
			  BSG_TPM_ENCAUTH, KeyMigrationAuth); 
  memcpy(InBuf+InLength, *prgbKey, *pcKeySize);
  InLength += *pcKeySize;
  InLength += packAuth(InBuf+InLength, pAuth);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_RESULT, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH1_COMMAND) {
      // Extract the remaining output parameters
      TPM_KEY wrappedKey;
      
      i += BSG_Unpack(BSG_TPM_KEY, OutBuf+i, &wrappedKey);
      unpackAuth(pAuth, OutBuf+i);
      
      // Fill prgbKey
      BYTE tempBuf[1024];
      *pcKeySize = BSG_Pack(BSG_TPM_KEY, &wrappedKey, tempBuf);
      if (TCS_Malloc(hContext, *pcKeySize, prgbKey) == TPM_FAIL) 
        return TPM_SIZE;
      
      memcpy(*prgbKey, tempBuf, *pcKeySize);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_CreateWrapKey Failed with return code %s\n", tpm_get_error_name(returnCode)); 
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_LoadKeyByBlob(TCS_CONTEXT_HANDLE hContext,    // in
			      TCS_KEY_HANDLE  hUnwrappingKey,   // in
			      UINT32    cWrappedKeyBlobSize, // in
			      BYTE*    rgbWrappedKeyBlob,  // in
			      TCS_AUTH*   pAuth,     // in, out
			      TCS_KEY_HANDLE*  phKeyTCSI,    // out
			      TCS_KEY_HANDLE*  phKeyHMAC)    // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_AUTH1_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_LoadKey;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (rgbWrappedKeyBlob == NULL || pAuth == NULL || phKeyTCSI == NULL || phKeyHMAC == NULL) 
    return TPM_BAD_PARAMETER; 
  
  *phKeyHMAC = hUnwrappingKey; // the parent key is the one that the TPM use to make the HMAC calc
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 4, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &hUnwrappingKey);
  memcpy(InBuf+InLength, rgbWrappedKeyBlob, cWrappedKeyBlobSize);
  InLength += cWrappedKeyBlobSize;
  InLength += packAuth(InBuf+InLength, pAuth);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_AUTH1_COMMAND) {
      // Extract the remaining output parameters
      i += BSG_Unpack(BSG_TYPE_UINT32, 
		      OutBuf+i, 
		      phKeyTCSI);
      unpackAuth(pAuth, OutBuf+i);
      
      if (!AddHandleToList(hContext, TPM_RT_KEY, *phKeyTCSI)) {
        vtpmlogerror(VTPM_LOG_TCS, "New KeyHandle not recorded\n");
      }
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
     } else 
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_LoadKeyByBlob Failed with return code %s\n", tpm_get_error_name(returnCode));
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_EvictKey(TCS_CONTEXT_HANDLE hContext, // in
			 TCS_KEY_HANDLE  hKey)  // in
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_EvictKey;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 4, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, &hKey);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (!DeleteHandleFromList(hContext, hKey)) {
      vtpmlogerror(VTPM_LOG_TCS, "KeyHandle not removed from list\n");
    }	 
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else {
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_EvictKey Failed with return code %s\n", tpm_get_error_name(returnCode));
    }
  }
  
  return(returnCode);
}

TPM_RESULT TCSP_GetRandom(TCS_CONTEXT_HANDLE hContext,  // in
			  UINT32*    bytesRequested, // in, out
			  BYTE**    randomBytes) // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_GetRandom;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (bytesRequested == NULL || *randomBytes == NULL){
    return TPM_BAD_PARAMETER;
  }
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 4, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TYPE_UINT32, bytesRequested);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      // Extract the remaining output parameters
      BSG_Unpack(BSG_TYPE_UINT32, OutBuf+i, bytesRequested);
      if (TCS_Malloc(hContext, *bytesRequested, randomBytes) == TPM_FAIL) {
        return TPM_SIZE;
      }
      memcpy(*randomBytes, OutBuf+i+sizeof(UINT32), *bytesRequested);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else {
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_GetRandom Failed with return code %s\n", tpm_get_error_name(returnCode));
    }
  }
  
  return(returnCode);
}


TPM_RESULT TCSP_ReadPubek(TCS_CONTEXT_HANDLE   hContext,               // in
			  TPM_NONCE            antiReplay,             // in
			  UINT32*              pubEndorsementKeySize,  // out
			  BYTE**               pubEndorsementKey,      // out
			  TPM_DIGEST*          checksum)               // out
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_ReadPubek;
  TPM_RESULT returnCode = TPM_SUCCESS;
  
  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32   OutLength = TCPA_MAX_BUFFER_LENGTH;
  
  // check input params
  if (pubEndorsementKeySize == NULL || pubEndorsementKey == NULL || checksum == NULL) {
    return TPM_BAD_PARAMETER;
  }
  
  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 4, 
			  BSG_TPM_TAG, &tag, 
			  BSG_TYPE_UINT32, &paramSize, 
			  BSG_TPM_COMMAND_CODE, &ordinal, 
			  BSG_TPM_NONCE, &antiReplay);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);
  
  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);
  
  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    int i = BSG_UnpackList(OutBuf, 3, 
			   BSG_TPM_TAG, &tag, 
			   BSG_TYPE_UINT32, &paramSize, 
			   BSG_TPM_COMMAND_CODE, &returnCode);
    
    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      // Extract the remaining output parameters
      TPM_PUBKEY pubEK;
      i += BSG_UnpackList(OutBuf+i, 2, 
			  BSG_TPM_PUBKEY, &pubEK, 
			  BSG_TPM_DIGEST, checksum);
      
      // fill EndorsementKey
      BYTE tempBuf[1024];
      *pubEndorsementKeySize = BSG_Pack(BSG_TPM_PUBKEY, &pubEK, tempBuf);
      if (TCS_Malloc(hContext, *pubEndorsementKeySize, pubEndorsementKey) == TPM_FAIL) {
        return TPM_SIZE;
      }
      memcpy(*pubEndorsementKey, tempBuf, *pubEndorsementKeySize);
      
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else {
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_ReadPubek Failed with return code %s\n", tpm_get_error_name(returnCode));
    }
  }
  
  return(returnCode);
}


TPM_RESULT TCSP_SaveState(TCS_CONTEXT_HANDLE   hContext)  // in
{
  // setup input/output parameters block
  TPM_TAG tag = TPM_TAG_RQU_COMMAND;
  UINT32 paramSize = 0;
  TPM_COMMAND_CODE ordinal = TPM_ORD_SaveState;
  TPM_RESULT returnCode = TPM_SUCCESS;

  // setup the TPM driver input and output buffers
  TDDL_RESULT hRes = TDDL_E_FAIL;
  TDDL_UINT32  InLength = TCPA_MAX_BUFFER_LENGTH;
  TDDL_UINT32  OutLength = TCPA_MAX_BUFFER_LENGTH;

  // Convert Byte Input parameter in the input byte stream InBuf
  InLength = BSG_PackList(InBuf, 3,
                          BSG_TPM_TAG, &tag,
                          BSG_TYPE_UINT32, &paramSize,
                          BSG_TPM_COMMAND_CODE, &ordinal);
  // fill paramSize again as we now have the correct size
  BSG_Pack(BSG_TYPE_UINT32, &InLength, InBuf+2);

  vtpmloginfo(VTPM_LOG_TCS_DEEP, "Sending paramSize = %d\n", InLength);

  // call the TPM driver
  if ((hRes = TDDL_TransmitData(InBuf, InLength, OutBuf, &OutLength)) == TDDL_SUCCESS) {
    // unpack OutBuf to get the tag, paramSize, & returnCode
    BSG_UnpackList(OutBuf, 3,
                           BSG_TPM_TAG, &tag,
                           BSG_TYPE_UINT32, &paramSize,
                           BSG_TPM_COMMAND_CODE, &returnCode);

    if (returnCode == TPM_SUCCESS && tag == TPM_TAG_RSP_COMMAND) {
      vtpmloginfo(VTPM_LOG_TCS_DEEP, "Received paramSize : %d\n", paramSize);
    } else {
      vtpmlogerror(VTPM_LOG_TCS, "TCSP_SaveState Failed with return code %s\n", tpm_get_error_name(returnCode));
    }
  }

  return(returnCode);
}


TPM_RESULT TCSP_RawTransmitData(   UINT32 inDataSize,  // in
				   BYTE *inData,       // in
				   UINT32 *outDataSize,// in/out
				   BYTE *outData) {    // out     
  
  TDDL_RESULT hRes;
  
  vtpmloginfo(VTPM_LOG_TCS, "Calling TransmitData directly.\n");
  //FIXME: Add Context Management
  hRes = TDDL_TransmitData( inData, 
			    inDataSize, 
			    outData, 
			    outDataSize);
  
  if (hRes == TDDL_SUCCESS) {
    return TPM_SUCCESS;
  } else {
    vtpmlogerror(VTPM_LOG_TCS, "TCSP_RawTransmitData Failed with return code %s\n", tpm_get_error_name(TPM_IOERROR));
    return TPM_IOERROR;
  }
  
}
