/*
 * Copyright (c) 2010-2012 United States Government, as represented by
 * the Secretary of Defense.  All rights reserved.
 *
 * based off of the original tools/vtpm_manager code base which is:
 * Copyright (c) 2005, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <stdint.h>
#include <stdlib.h>

#include <xen/xen.h>
#include <mini-os/tpmback.h>
#include <mini-os/tpmfront.h>
#include <mini-os/tpm_tis.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <polarssl/sha1.h>

#include "log.h"
#include "vtpmmgr.h"
#include "vtpm_disk.h"
#include "tpm.h"
#include "marshal.h"

struct Opts {
   enum {
      TPMDRV_TPM_TIS,
      TPMDRV_TPMFRONT,
   } tpmdriver;
   unsigned long tpmiomem;
   unsigned int tpmirq;
   unsigned int tpmlocality;
   int gen_owner_auth;
};

// --------------------------- Well Known Auths --------------------------
const TPM_AUTHDATA WELLKNOWN_AUTH = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

struct vtpm_globals vtpm_globals = {
   .tpm_fd = -1,
   .oiap = { .AuthHandle = 0 },
   .hw_locality = 0
};

static int tpm_entropy_source(void* dummy, unsigned char* data, size_t len, size_t* olen) {
   UINT32 sz = len;
   TPM_RESULT rc = TPM_GetRandom(&sz, data);
   *olen = sz;
   return rc == TPM_SUCCESS ? 0 : POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
}

static TPM_RESULT check_tpm_version(void) {
   TPM_RESULT status;
   UINT32 rsize;
   BYTE* res = NULL;
   TPM_CAP_VERSION_INFO vinfo;

   TPMTRYRETURN(TPM_GetCapability(
            TPM_CAP_VERSION_VAL,
            0,
            NULL,
            &rsize,
            &res));
   if(rsize < 4) {
      vtpmlogerror(VTPM_LOG_VTPM, "Invalid size returned by GetCapability!\n");
      status = TPM_BAD_PARAMETER;
      goto abort_egress;
   }

   unpack_TPM_CAP_VERSION_INFO(res, &vinfo, UNPACK_ALIAS);

   vtpmloginfo(VTPM_LOG_VTPM, "Hardware TPM:\n");
   vtpmloginfo(VTPM_LOG_VTPM, " version: %hhd %hhd %hhd %hhd\n",
         vinfo.version.major, vinfo.version.minor, vinfo.version.revMajor, vinfo.version.revMinor);
   vtpmloginfo(VTPM_LOG_VTPM, " specLevel: %hd\n", vinfo.specLevel);
   vtpmloginfo(VTPM_LOG_VTPM, " errataRev: %hhd\n", vinfo.errataRev);
   vtpmloginfo(VTPM_LOG_VTPM, " vendorID: %c%c%c%c\n",
         vinfo.tpmVendorID[0], vinfo.tpmVendorID[1],
         vinfo.tpmVendorID[2], vinfo.tpmVendorID[3]);
   vtpmloginfo(VTPM_LOG_VTPM, " vendorSpecificSize: %hd\n", vinfo.vendorSpecificSize);
   vtpmloginfo(VTPM_LOG_VTPM, " vendorSpecific: ");
   for(int i = 0; i < vinfo.vendorSpecificSize; ++i) {
      vtpmloginfomore(VTPM_LOG_VTPM, "%02hhx", vinfo.vendorSpecific[i]);
   }
   vtpmloginfomore(VTPM_LOG_VTPM, "\n");

abort_egress:
   free(res);
   return status;
}

static TPM_RESULT flush_tpm(void) {
   TPM_RESULT status = TPM_SUCCESS;
   const TPM_RESOURCE_TYPE reslist[] = { TPM_RT_KEY, TPM_RT_AUTH, TPM_RT_TRANS, TPM_RT_COUNTER, TPM_RT_DAA_TPM, TPM_RT_CONTEXT };
   BYTE* keylist = NULL;
   UINT32 keylistSize;
   BYTE* ptr;

   //Iterate through each resource type and flush all handles
   for(int i = 0; i < sizeof(reslist) / sizeof(TPM_RESOURCE_TYPE); ++i) {
      TPM_RESOURCE_TYPE beres = cpu_to_be32(reslist[i]);
      UINT16 size;
      TPMTRYRETURN(TPM_GetCapability(
               TPM_CAP_HANDLE,
               sizeof(TPM_RESOURCE_TYPE),
               (BYTE*)(&beres),
               &keylistSize,
               &keylist));

      ptr = keylist;
      ptr = unpack_UINT16(ptr, &size);

      //Flush each handle
      if(size) {
         vtpmloginfo(VTPM_LOG_VTPM, "Flushing %u handle(s) of type %lu\n", size, (unsigned long) reslist[i]);
         for(int j = 0; j < size; ++j) {
            TPM_HANDLE h;
            ptr = unpack_TPM_HANDLE(ptr, &h);
            TPMTRYRETURN(TPM_FlushSpecific(h, reslist[i]));
         }
      }

      free(keylist);
      keylist = NULL;
   }

   goto egress;
abort_egress:
   free(keylist);
egress:
   return status;
}


static TPM_RESULT try_take_ownership(void) {
   TPM_RESULT status = TPM_SUCCESS;
   TPM_PUBKEY pubEK = TPM_PUBKEY_INIT;

   // If we can read PubEK then there is no owner and we should take it.
   status = TPM_ReadPubek(&pubEK);

   switch(status) {
      case TPM_DISABLED_CMD:
         //Cannot read ek? TPM has owner
         vtpmloginfo(VTPM_LOG_VTPM, "Failed to readEK meaning TPM has an owner. Creating Keys off existing SRK.\n");
         status = TPM_SUCCESS;
         break;
      case TPM_NO_ENDORSEMENT:
         {
            //If theres no ek, we have to create one
            TPM_KEY_PARMS keyInfo = {
               .algorithmID = TPM_ALG_RSA,
               .encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1,
               .sigScheme = TPM_SS_NONE,
               .parmSize = 12,
               .parms.rsa = {
                  .keyLength = RSA_KEY_SIZE,
                  .numPrimes = 2,
                  .exponentSize = 0,
                  .exponent = NULL,
               },
            };
            TPMTRYRETURN(TPM_CreateEndorsementKeyPair(&keyInfo, &pubEK));
         }
         //fall through to take ownership
      case TPM_SUCCESS:
         {
            //Construct the Srk
            TPM_KEY srk = {
               .ver = TPM_STRUCT_VER_1_1,
               .keyUsage = TPM_KEY_STORAGE,
               .keyFlags = 0x00,
               .authDataUsage = TPM_AUTH_ALWAYS,
               .algorithmParms = {
                  .algorithmID = TPM_ALG_RSA,
                  .encScheme = TPM_ES_RSAESOAEP_SHA1_MGF1,
                  .sigScheme =  TPM_SS_NONE,
                  .parmSize = 12,
                  .parms.rsa = {
                     .keyLength = RSA_KEY_SIZE,
                     .numPrimes = 2,
                     .exponentSize = 0,
                     .exponent = NULL,
                  },
               },
               .PCRInfoSize = 0,
               .pubKey = {
                  .keyLength = 0,
                  .key = NULL,
               },
               .encDataSize = 0,
            };

            TPMTRYRETURN(TPM_TakeOwnership(
                     &pubEK,
                     (const TPM_AUTHDATA*)&vtpm_globals.owner_auth,
                     (const TPM_AUTHDATA*)&vtpm_globals.srk_auth,
                     &srk,
                     NULL,
                     &vtpm_globals.oiap));

            TPMTRYRETURN(TPM_DisablePubekRead(
                     (const TPM_AUTHDATA*)&vtpm_globals.owner_auth,
                     &vtpm_globals.oiap));
         }
         break;
      default:
         break;
   }
abort_egress:
   free_TPM_PUBKEY(&pubEK);
   return status;
}

static int parse_auth_string(char* authstr, BYTE* target) {
   int rc;
   /* well known owner auth */
   if(!strcmp(authstr, "well-known")) {
	   return 0;
   }
   /* owner auth is a raw hash */
   else if(!strncmp(authstr, "hash:", 5)) {
      authstr += 5;
      if((rc = strlen(authstr)) != 40) {
         vtpmlogerror(VTPM_LOG_VTPM, "Supplied owner auth hex string `%s' must be exactly 40 characters (20 bytes) long, length=%d\n", authstr, rc);
         return -1;
      }
      for(int j = 0; j < 20; ++j) {
         if(sscanf(authstr, "%hhX", target + j) != 1) {
            vtpmlogerror(VTPM_LOG_VTPM, "Supplied owner auth string `%s' is not a valid hex string\n", authstr);
            return -1;
         }
         authstr += 2;
      }
   }
   /* owner auth is a string that will be hashed */
   else if(!strncmp(authstr, "text:", 5)) {
      authstr += 5;
      sha1((const unsigned char*)authstr, strlen(authstr), target);
   }
   else {
      vtpmlogerror(VTPM_LOG_VTPM, "Invalid auth string %s\n", authstr);
      return -1;
   }

   return 0;
}

int parse_cmdline_opts(int argc, char** argv, struct Opts* opts)
{
   int rc;
   int i;

   //Set defaults
   memcpy(vtpm_globals.owner_auth, WELLKNOWN_AUTH, sizeof(TPM_AUTHDATA));
   memcpy(vtpm_globals.srk_auth, WELLKNOWN_AUTH, sizeof(TPM_AUTHDATA));

   for(i = 1; i < argc; ++i) {
      if(!strncmp(argv[i], "owner_auth:", 10)) {
         if((rc = parse_auth_string(argv[i] + 10, vtpm_globals.owner_auth)) < 0) {
            goto err_invalid;
         }
         if(rc == 1) {
            opts->gen_owner_auth = 1;
         }
      }
      else if(!strncmp(argv[i], "srk_auth:", 8)) {
         if((rc = parse_auth_string(argv[i] + 8, vtpm_globals.srk_auth)) != 0) {
            goto err_invalid;
         }
      }
      else if(!strncmp(argv[i], "tpmdriver=", 10)) {
         if(!strcmp(argv[i] + 10, "tpm_tis")) {
            opts->tpmdriver = TPMDRV_TPM_TIS;
         } else if(!strcmp(argv[i] + 10, "tpmfront")) {
            opts->tpmdriver = TPMDRV_TPMFRONT;
         } else {
            goto err_invalid;
         }
      }
      else if(!strncmp(argv[i], "tpmiomem=",9)) {
         if(sscanf(argv[i] + 9, "0x%lX", &opts->tpmiomem) != 1) {
            goto err_invalid;
         }
      }
      else if(!strncmp(argv[i], "tpmirq=",7)) {
         if(!strcmp(argv[i] + 7, "probe")) {
            opts->tpmirq = TPM_PROBE_IRQ;
         } else if( sscanf(argv[i] + 7, "%u", &opts->tpmirq) != 1) {
            goto err_invalid;
         }
      }
      else if(!strncmp(argv[i], "tpmlocality=",12)) {
         if(sscanf(argv[i] + 12, "%u", &opts->tpmlocality) != 1 || opts->tpmlocality > 4) {
            goto err_invalid;
         }
      }
   }

   switch(opts->tpmdriver) {
      case TPMDRV_TPM_TIS:
         vtpmloginfo(VTPM_LOG_VTPM, "Option: Using tpm_tis driver\n");
         break;
      case TPMDRV_TPMFRONT:
         vtpmloginfo(VTPM_LOG_VTPM, "Option: Using tpmfront driver\n");
         break;
   }

   return 0;
err_invalid:
   vtpmlogerror(VTPM_LOG_VTPM, "Invalid Option %s\n", argv[i]);
   return -1;
}



static TPM_RESULT vtpmmgr_create(void) {
   TPM_RESULT status = TPM_SUCCESS;
   TPM_AUTH_SESSION osap = TPM_AUTH_SESSION_INIT;
   TPM_AUTHDATA sharedsecret;

   // Take ownership if TPM is unowned
   TPMTRYRETURN(try_take_ownership());

   // Generate storage key's auth
   TPMTRYRETURN( TPM_OSAP(
            TPM_ET_KEYHANDLE,
            TPM_SRK_KEYHANDLE,
            (const TPM_AUTHDATA*)&vtpm_globals.srk_auth,
            &sharedsecret,
            &osap) );

   //Make sure TPM has commited changes
   TPMTRYRETURN( TPM_SaveState() );

   //Create new disk image
   TPMTRYRETURN(vtpm_new_disk());

   goto egress;
abort_egress:
egress:
   vtpmloginfo(VTPM_LOG_VTPM, "Finished initialized new VTPM manager\n");

   //End the OSAP session
   if(osap.AuthHandle) {
      TPM_TerminateHandle(osap.AuthHandle);
   }

   return status;
}

static void set_opaque(domid_t domid, unsigned int handle)
{
	struct tpm_opaque* opq;

	opq = calloc(1, sizeof(*opq));
	opq->uuid = (uuid_t*)tpmback_get_uuid(domid, handle);
	opq->domid = domid;
	opq->handle = handle;
	tpmback_set_opaque(domid, handle, opq);
}

static void free_opaque(domid_t domid, unsigned int handle)
{
	struct tpm_opaque* opq = tpmback_get_opaque(domid, handle);
	if (opq && opq->vtpm)
		opq->vtpm->flags &= ~VTPM_FLAG_OPEN;
	free(opq);
}

TPM_RESULT vtpmmgr_init(int argc, char** argv) {
   TPM_RESULT status = TPM_SUCCESS;

   /* Default commandline options */
   struct Opts opts = {
      .tpmdriver = TPMDRV_TPM_TIS,
      .tpmiomem = TPM_BASEADDR,
      .tpmirq = 0,
      .tpmlocality = 0,
      .gen_owner_auth = 0,
   };

   if(parse_cmdline_opts(argc, argv, &opts) != 0) {
      vtpmlogerror(VTPM_LOG_VTPM, "Command line parsing failed! exiting..\n");
      status = TPM_BAD_PARAMETER;
      goto abort_egress;
   }

   //Setup storage system
   if(vtpm_storage_init() != 0) {
      vtpmlogerror(VTPM_LOG_VTPM, "Unable to initialize storage subsystem!\n");
      status = TPM_IOERROR;
      goto abort_egress;
   }

   //Setup tpmback device
   init_tpmback(set_opaque, free_opaque);

   //Setup tpm access
   switch(opts.tpmdriver) {
      case TPMDRV_TPM_TIS:
         {
            struct tpm_chip* tpm;
            if((tpm = init_tpm_tis(opts.tpmiomem, TPM_TIS_LOCL_INT_TO_FLAG(opts.tpmlocality), opts.tpmirq)) == NULL) {
               vtpmlogerror(VTPM_LOG_VTPM, "Unable to initialize tpmfront device\n");
               status = TPM_IOERROR;
               goto abort_egress;
            }
            vtpm_globals.tpm_fd = tpm_tis_open(tpm);
            tpm_tis_request_locality(tpm, opts.tpmlocality);
            vtpm_globals.hw_locality = opts.tpmlocality;
         }
         break;
      case TPMDRV_TPMFRONT:
         {
            struct tpmfront_dev* tpmfront_dev;
            if((tpmfront_dev = init_tpmfront(NULL)) == NULL) {
               vtpmlogerror(VTPM_LOG_VTPM, "Unable to initialize tpmfront device\n");
               status = TPM_IOERROR;
               goto abort_egress;
            }
            vtpm_globals.tpm_fd = tpmfront_open(tpmfront_dev);
         }
         break;
   }

   //Get the version of the tpm
   TPMTRYRETURN(check_tpm_version());

   // Blow away all stale handles left in the tpm
   if(flush_tpm() != TPM_SUCCESS) {
      vtpmlogerror(VTPM_LOG_VTPM, "VTPM_FlushResources failed, continuing anyway..\n");
   }

   /* Initialize the rng */
   entropy_init(&vtpm_globals.entropy);
   entropy_add_source(&vtpm_globals.entropy, tpm_entropy_source, NULL, 0);
   entropy_gather(&vtpm_globals.entropy);
   ctr_drbg_init(&vtpm_globals.ctr_drbg, entropy_func, &vtpm_globals.entropy, NULL, 0);
   ctr_drbg_set_prediction_resistance( &vtpm_globals.ctr_drbg, CTR_DRBG_PR_OFF );

   // Generate Auth for Owner
   if(opts.gen_owner_auth) {
      vtpmmgr_rand(vtpm_globals.owner_auth, sizeof(TPM_AUTHDATA));
   }

   // Create OIAP session for service's authorized commands
   TPMTRYRETURN( TPM_OIAP(&vtpm_globals.oiap) );

   /* Load the Manager data, if it fails create a new manager */
   // TODO handle upgrade recovery of auth0
   if (vtpm_load_disk()) {
      /* If the OIAP session was closed by an error, create a new one */
      if(vtpm_globals.oiap.AuthHandle == 0) {
         TPMTRYRETURN( TPM_OIAP(&vtpm_globals.oiap) );
      }
      vtpmloginfo(VTPM_LOG_VTPM, "Failed to read manager file. Assuming first time initialization.\n");
      TPMTRYRETURN( vtpmmgr_create() );
   }

   goto egress;
abort_egress:
   vtpmmgr_shutdown();
egress:
   return status;
}

void vtpmmgr_shutdown(void)
{
   /* Cleanup TPM resources */
   TPM_TerminateHandle(vtpm_globals.oiap.AuthHandle);

   /* Close tpmback */
   shutdown_tpmback();

   /* Close tpmfront/tpm_tis */
   close(vtpm_globals.tpm_fd);

   vtpmloginfo(VTPM_LOG_VTPM, "VTPM Manager stopped.\n");
}
