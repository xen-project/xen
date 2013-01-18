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

#include "vtpm_pcrs.h"
#include "vtpm_cmd.h"
#include "tpm/tpm_data.h"

#define PCR_VALUE      tpmData.permanent.data.pcrValue

static int write_pcr_direct(unsigned int pcrIndex, uint8_t* val) {
   if(pcrIndex > TPM_NUM_PCR) {
      return TPM_BADINDEX;
   }
   memcpy(&PCR_VALUE[pcrIndex], val, sizeof(TPM_PCRVALUE));
   return TPM_SUCCESS;
}

TPM_RESULT vtpm_initialize_hw_pcrs(struct tpmfront_dev* tpmfront_dev, unsigned long pcrs)
{
   TPM_RESULT rc = TPM_SUCCESS;
   uint8_t digest[sizeof(TPM_PCRVALUE)];

   for(unsigned int i = 0; i < TPM_NUM_PCR; ++i) {
      if(pcrs & 1 << i) {
         if((rc = VTPM_PCRRead(tpmfront_dev, i, digest)) != TPM_SUCCESS) {
            error("TPM_PCRRead failed with error : %d", rc);
            return rc;
         }
         write_pcr_direct(i, digest);
      }
   }

   return rc;
}
