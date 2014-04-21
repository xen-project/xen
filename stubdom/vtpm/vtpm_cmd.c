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

#include <types.h>
#include <xen/xen.h>
#include <mm.h>
#include <gnttab.h>
#include "tpm/tpm_marshalling.h"
#include "vtpm_manager.h"
#include "vtpm_cmd.h"
#include <tpmback.h>

#define TRYFAILGOTO(C) \
   if((C)) { \
      status = TPM_FAIL; \
      goto abort_egress; \
   }
#define TRYFAILGOTOMSG(C, msg) \
   if((C)) { \
      status = TPM_FAIL; \
      error(msg); \
      goto abort_egress; \
   }
#define CHECKSTATUSGOTO(ret, fname) \
   if((ret) != TPM_SUCCESS) { \
      error("%s failed with error code (%lu)", fname, (unsigned long) ret); \
      status = ord; \
      goto abort_egress; \
   }

#define ERR_MALFORMED "Malformed response from backend"
#define ERR_TPMFRONT "Error sending command through frontend device"

struct shpage {
   void* page;
   grant_ref_t grantref;
};

typedef struct shpage shpage_t;

static inline int pack_header(uint8_t** bptr, UINT32* len, TPM_TAG tag, UINT32 size, TPM_COMMAND_CODE ord)
{
   return *bptr == NULL ||
	 tpm_marshal_UINT16(bptr, len, tag) ||
	 tpm_marshal_UINT32(bptr, len, size) ||
	 tpm_marshal_UINT32(bptr, len, ord);
}

static inline int unpack_header(uint8_t** bptr, UINT32* len, TPM_TAG* tag, UINT32* size, TPM_COMMAND_CODE* ord)
{
   return *bptr == NULL ||
	 tpm_unmarshal_UINT16(bptr, len, tag) ||
	 tpm_unmarshal_UINT32(bptr, len, size) ||
	 tpm_unmarshal_UINT32(bptr, len, ord);
}

int create_error_response(tpmcmd_t* tpmcmd, TPM_RESULT errorcode)
{
   TPM_TAG tag;
   UINT32 len = tpmcmd->req_len;
   uint8_t* respptr;
   uint8_t* cmdptr = tpmcmd->req;

   if(!tpm_unmarshal_UINT16(&cmdptr, &len, &tag)) {
      switch (tag) {
         case TPM_TAG_RQU_COMMAND:
            tag = TPM_TAG_RSP_COMMAND;
            break;
         case TPM_TAG_RQU_AUTH1_COMMAND:
            tag = TPM_TAG_RQU_AUTH2_COMMAND;
            break;
         case TPM_TAG_RQU_AUTH2_COMMAND:
            tag = TPM_TAG_RQU_AUTH2_COMMAND;
            break;
      }
   } else {
      tag = TPM_TAG_RSP_COMMAND;
   }

   tpmcmd->resp_len = len = 10;
   tpmcmd->resp = respptr = tpm_malloc(tpmcmd->resp_len);

   return pack_header(&respptr, &len, tag, len, errorcode);
}

TPM_RESULT VTPM_GetRandom(struct tpmfront_dev* tpmfront_dev, BYTE* bytes, UINT32 *numbytes) {
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t* cmdbuf, *resp, *bptr;
   size_t resplen = 0;
   UINT32 len;

   /*Ask the real tpm for random bytes for the seed */
   TPM_TAG tag = TPM_TAG_RQU_COMMAND;
   UINT32 size;
   TPM_COMMAND_CODE ord = TPM_ORD_GetRandom;
   len = size = sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) + sizeof(UINT32);

   /*Create the raw tpm command */
   bptr = cmdbuf = malloc(size);
   TRYFAILGOTO(pack_header(&bptr, &len, tag, size, ord));
   TRYFAILGOTO(tpm_marshal_UINT32(&bptr, &len, *numbytes));

   /* Send cmd, wait for response */
   TRYFAILGOTOMSG(tpmfront_cmd(tpmfront_dev, cmdbuf, size, &resp, &resplen),
      ERR_TPMFRONT);

   bptr = resp; len = resplen;
   TRYFAILGOTOMSG(unpack_header(&bptr, &len, &tag, &size, &ord), ERR_MALFORMED);

   //Check return status of command
   CHECKSTATUSGOTO(ord, "TPM_GetRandom()");

   // Get the number of random bytes in the response
   TRYFAILGOTOMSG(tpm_unmarshal_UINT32(&bptr, &len, &size), ERR_MALFORMED);
   *numbytes = size;

   //Get the random bytes out, tpm may give us less bytes than what we wanrt
   TRYFAILGOTOMSG(tpm_unmarshal_BYTE_ARRAY(&bptr, &len, bytes, *numbytes), ERR_MALFORMED);

   goto egress;
abort_egress:
egress:
   free(cmdbuf);
   return status;

}

TPM_RESULT VTPM_LoadHashKey(struct tpmfront_dev* tpmfront_dev, uint8_t** data, size_t* data_length)
{
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t* bptr, *resp;
   uint8_t* cmdbuf = NULL;
   size_t resplen = 0;
   UINT32 len;

   TPM_TAG tag = VTPM_TAG_REQ;
   UINT32 size;
   TPM_COMMAND_CODE ord = VTPM_ORD_LOADHASHKEY;

   /*Create the command*/
   len = size = VTPM_COMMAND_HEADER_SIZE;
   bptr = cmdbuf = malloc(size);
   TRYFAILGOTO(pack_header(&bptr, &len, tag, size, ord));

   /* Send the command to vtpm_manager */
   info("Requesting Encryption key from backend");
   TRYFAILGOTOMSG(tpmfront_cmd(tpmfront_dev, cmdbuf, size, &resp, &resplen), ERR_TPMFRONT);

   /* Unpack response header */
   bptr = resp;
   len = resplen;
   TRYFAILGOTOMSG(unpack_header(&bptr, &len, &tag, &size, &ord), ERR_MALFORMED);

   /* Check return code */
   CHECKSTATUSGOTO(ord, "VTPM_LoadHashKey()");

   /* Get the size of the key */
   *data_length = size - VTPM_COMMAND_HEADER_SIZE;

   /* Copy the key bits */
   *data = malloc(*data_length);
   memcpy(*data, bptr, *data_length);

   goto egress;
abort_egress:
   error("VTPM_LoadHashKey failed");
egress:
   free(cmdbuf);
   return status;
}

TPM_RESULT VTPM_SaveHashKey(struct tpmfront_dev* tpmfront_dev, uint8_t* data, size_t data_length)
{
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t* bptr, *resp;
   uint8_t* cmdbuf = NULL;
   size_t resplen = 0;
   UINT32 len;

   TPM_TAG tag = VTPM_TAG_REQ;
   UINT32 size;
   TPM_COMMAND_CODE ord = VTPM_ORD_SAVEHASHKEY;

   /*Create the command*/
   len = size = VTPM_COMMAND_HEADER_SIZE + data_length;
   bptr = cmdbuf = malloc(size);
   TRYFAILGOTO(pack_header(&bptr, &len, tag, size, ord));
   memcpy(bptr, data, data_length);
   bptr += data_length;

   /* Send the command to vtpm_manager */
   info("Sending encryption key to backend");
   TRYFAILGOTOMSG(tpmfront_cmd(tpmfront_dev, cmdbuf, size, &resp, &resplen), ERR_TPMFRONT);

   /* Unpack response header */
   bptr = resp;
   len = resplen;
   TRYFAILGOTOMSG(unpack_header(&bptr, &len, &tag, &size, &ord), ERR_MALFORMED);

   /* Check return code */
   CHECKSTATUSGOTO(ord, "VTPM_SaveHashKey()");

   goto egress;
abort_egress:
   error("VTPM_SaveHashKey failed");
egress:
   free(cmdbuf);
   return status;
}

extern struct tpmfront_dev* tpmfront_dev;
TPM_RESULT VTPM_GetParentQuote(TPM_NONCE *data, TPM_PCR_SELECTION *sel, UINT32 *sigSize, BYTE **sig)
{
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t* bptr, *resp;
   uint8_t* cmdbuf = NULL;
   size_t resplen = 0;
   UINT32 len;

   TPM_TAG tag = VTPM_TAG_REQ;
   UINT32 size;
   TPM_COMMAND_CODE ord = VTPM_ORD_GET_QUOTE;

   /*Create the command*/
   len = size = VTPM_COMMAND_HEADER_SIZE + 25;
   bptr = cmdbuf = malloc(size);
   TRYFAILGOTO(pack_header(&bptr, &len, tag, size, ord));
   TRYFAILGOTO(tpm_marshal_TPM_NONCE(&bptr, &len, data));
   TRYFAILGOTO(tpm_marshal_TPM_PCR_SELECTION(&bptr, &len, sel));

   /* Send the command to vtpm_manager */
   info("Requesting Quote from backend");
   TRYFAILGOTOMSG(tpmfront_cmd(tpmfront_dev, cmdbuf, size, &resp, &resplen), ERR_TPMFRONT);

   /* Unpack response header */
   bptr = resp;
   len = resplen;
   TRYFAILGOTOMSG(unpack_header(&bptr, &len, &tag, &size, &ord), ERR_MALFORMED);

   /* Check return code */
   CHECKSTATUSGOTO(ord, "VTPM_GetParentQuote()");

   /* Copy out the value */
   *sigSize = len;
   *sig = tpm_malloc(*sigSize);
   TRYFAILGOTOMSG(tpm_unmarshal_BYTE_ARRAY(&bptr, &len, *sig, *sigSize), ERR_MALFORMED);

   goto egress;
abort_egress:
   error("VTPM_GetParentQuote failed");
egress:
   free(cmdbuf);
   return status;
}

TPM_RESULT VTPM_PCRRead(struct tpmfront_dev* tpmfront_dev, UINT32 pcrIndex, BYTE* outDigest)
{
   TPM_RESULT status = TPM_SUCCESS;
   uint8_t *cmdbuf, *resp, *bptr;
   size_t resplen = 0;
   UINT32 len;

   /*Just send a TPM_PCRRead Command to the HW tpm */
   TPM_TAG tag = TPM_TAG_RQU_COMMAND;
   UINT32 size;
   TPM_COMMAND_CODE ord = TPM_ORD_PCRRead;
   len = size = sizeof(TPM_TAG) + sizeof(UINT32) + sizeof(TPM_COMMAND_CODE) + sizeof(UINT32);

   /*Create the raw tpm cmd */
   bptr = cmdbuf = malloc(size);
   TRYFAILGOTO(pack_header(&bptr, &len, tag, size, ord));
   TRYFAILGOTO(tpm_marshal_UINT32(&bptr, &len, pcrIndex));

   /*Send Cmd wait for response */
   TRYFAILGOTOMSG(tpmfront_cmd(tpmfront_dev, cmdbuf, size, &resp, &resplen), ERR_TPMFRONT);

   bptr = resp; len = resplen;
   TRYFAILGOTOMSG(unpack_header(&bptr, &len, &tag, &size, &ord), ERR_MALFORMED);

   //Check return status of command
   CHECKSTATUSGOTO(ord, "TPM_PCRRead");

   //Get the ptr value
   memcpy(outDigest, bptr, sizeof(TPM_PCRVALUE));

   goto egress;
abort_egress:
egress:
   free(cmdbuf);
   return status;

}
