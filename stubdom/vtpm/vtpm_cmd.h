/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * THIS SOFTWARE AND ITS DOCUMENTATION ARE PROVIDED AS IS AND WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTIES WHATSOEVER. ALL WARRANTIES
 * INCLUDING, BUT NOT LIMITED TO, PERFORMANCE, MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR  PURPOSE, AND NONINFRINGEMENT ARE HEREBY
 * DISCLAIMED. USERS ASSUME THE ENTIRE RISK AND LIABILITY OF USING THE
 * SOFTWARE.
 */

#ifndef MANAGER_H
#define MANAGER_H

#include <tpmfront.h>
#include <tpmback.h>
#include "tpm/tpm_structures.h"

/* Create a command response error header */
int create_error_response(tpmcmd_t* tpmcmd, TPM_RESULT errorcode);
/* Request random bytes from hardware tpm, returns 0 on success */
TPM_RESULT VTPM_GetRandom(struct tpmfront_dev* tpmfront_dev, BYTE* bytes, UINT32* numbytes);
/* Retreive 256 bit AES encryption key from manager */
TPM_RESULT VTPM_LoadHashKey(struct tpmfront_dev* tpmfront_dev, uint8_t** data, size_t* data_length);
/* Manager securely saves our 256 bit AES encryption key */
TPM_RESULT VTPM_SaveHashKey(struct tpmfront_dev* tpmfront_dev, uint8_t* data, size_t data_length);
/* Send a TPM_PCRRead command passthrough the manager to the hw tpm */
TPM_RESULT VTPM_PCRRead(struct tpmfront_dev* tpmfront_dev, UINT32 pcrIndex, BYTE* outDigest);

#endif
