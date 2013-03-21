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

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <xen/xen.h>
#include <tpmback.h>
#include <tpmfront.h>

#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "tpm/tpm_emulator_extern.h"
#include "tpm/tpm_marshalling.h"
#include "vtpm.h"
#include "vtpm_cmd.h"
#include "vtpm_pcrs.h"
#include "vtpmblk.h"

#define TPM_LOG_INFO LOG_INFO
#define TPM_LOG_ERROR LOG_ERR
#define TPM_LOG_DEBUG LOG_DEBUG

/* Global commandline options - default values */
struct Opt_args opt_args = {
   .startup = ST_CLEAR,
   .loglevel = TPM_LOG_INFO,
   .hwinitpcrs = VTPM_PCRNONE,
   .tpmconf = 0,
   .enable_maint_cmds = false,
};

static uint32_t badords[32];
static unsigned int n_badords = 0;

entropy_context entropy;
ctr_drbg_context ctr_drbg;

struct tpmfront_dev* tpmfront_dev;

void vtpm_get_extern_random_bytes(void *buf, size_t nbytes)
{
   ctr_drbg_random(&ctr_drbg, buf, nbytes);
}

int vtpm_read_from_file(uint8_t **data, size_t *data_length) {
   return read_vtpmblk(tpmfront_dev, data, data_length);
}

int vtpm_write_to_file(uint8_t *data, size_t data_length) {
   return write_vtpmblk(tpmfront_dev, data, data_length);
}

int vtpm_extern_init_fake(void) {
   return 0;
}

void vtpm_extern_release_fake(void) {
}


void vtpm_log(int priority, const char *fmt, ...)
{
   if(opt_args.loglevel >= priority) {
      va_list v;
      va_start(v, fmt);
      vprintf(fmt, v);
      va_end(v);
   }
}

static uint64_t vtpm_get_ticks(void)
{
  static uint64_t old_t = 0;
  uint64_t new_t, res_t;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  new_t = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
  res_t = (old_t > 0) ? new_t - old_t : 0;
  old_t = new_t;
  return res_t;
}


static int tpm_entropy_source(void* dummy, unsigned char* data, size_t len, size_t* olen) {
   UINT32 sz = len;
   TPM_RESULT rc = VTPM_GetRandom(tpmfront_dev, data, &sz);
   *olen = sz;
   return rc == TPM_SUCCESS ? 0 : POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
}

int init_random(void) {
   /* Initialize the rng */
   entropy_init(&entropy);
   entropy_add_source(&entropy, tpm_entropy_source, NULL, 0);
   entropy_gather(&entropy);
   ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, NULL, 0);
   ctr_drbg_set_prediction_resistance( &ctr_drbg, CTR_DRBG_PR_OFF );

   return 0;
}

int check_ordinal(tpmcmd_t* tpmcmd) {
   TPM_COMMAND_CODE ord;
   UINT32 len = 4;
   BYTE* ptr;
   unsigned int i;

   if(tpmcmd->req_len < 10) {
      return true;
   }

   ptr = tpmcmd->req + 6;
   tpm_unmarshal_UINT32(&ptr, &len, &ord);

   for(i = 0; i < n_badords; ++i) {
      if(ord == badords[i]) {
         error("Disabled command ordinal (%" PRIu32") requested!\n");
         return false;
      }
   }
   return true;
}

static void main_loop(void) {
   tpmcmd_t* tpmcmd = NULL;
   domid_t domid;		/* Domid of frontend */
   unsigned int handle;	/* handle of frontend */
   int res = -1;

   info("VTPM Initializing\n");

   /* Set required tpm config args */
   opt_args.tpmconf |= TPM_CONF_STRONG_PERSISTENCE;
   opt_args.tpmconf &= ~TPM_CONF_USE_INTERNAL_PRNG;
   opt_args.tpmconf |= TPM_CONF_GENERATE_EK;
   opt_args.tpmconf |= TPM_CONF_GENERATE_SEED_DAA;

   /* Initialize the emulator */
   tpm_emulator_init(opt_args.startup, opt_args.tpmconf);

   /* Initialize any requested PCRs with hardware TPM values */
   if(vtpm_initialize_hw_pcrs(tpmfront_dev, opt_args.hwinitpcrs) != TPM_SUCCESS) {
      error("Failed to initialize PCRs with hardware TPM values");
      goto abort_postpcrs;
   }

   /* Wait for the frontend domain to connect */
   info("Waiting for frontend domain to connect..");
   if(tpmback_wait_for_frontend_connect(&domid, &handle) == 0) {
      info("VTPM attached to Frontend %u/%u", (unsigned int) domid, handle);
   } else {
      error("Unable to attach to a frontend");
   }

   tpmcmd = tpmback_req(domid, handle);
   while(tpmcmd) {
      /* Handle the request */
      if(tpmcmd->req_len) {
	 tpmcmd->resp = NULL;
	 tpmcmd->resp_len = 0;

         /* First check for disabled ordinals */
         if(!check_ordinal(tpmcmd)) {
            create_error_response(tpmcmd, TPM_BAD_ORDINAL);
         }
         /* If not disabled, do the command */
         else {
            if((res = tpm_handle_command(tpmcmd->req, tpmcmd->req_len, &tpmcmd->resp, &tpmcmd->resp_len, tpmcmd->locality)) != 0) {
               error("tpm_handle_command() failed");
               create_error_response(tpmcmd, TPM_FAIL);
            }
         }
      }

      /* Send the response */
      tpmback_resp(tpmcmd);

      /* Wait for the next request */
      tpmcmd = tpmback_req(domid, handle);

   }

abort_postpcrs:
   info("VTPM Shutting down\n");

   tpm_emulator_shutdown();
}

int parse_cmd_line(int argc, char** argv)
{
   char sval[25];
   char* logstr = NULL;
   /* Parse the command strings */
   for(unsigned int i = 1; i < argc; ++i) {
      if (sscanf(argv[i], "loglevel=%25s", sval) == 1){
	 if (!strcmp(sval, "debug")) {
	    opt_args.loglevel = TPM_LOG_DEBUG;
	    logstr = "debug";
	 }
	 else if (!strcmp(sval, "info")) {
	    logstr = "info";
	    opt_args.loglevel = TPM_LOG_INFO;
	 }
	 else if (!strcmp(sval, "error")) {
	    logstr = "error";
	    opt_args.loglevel = TPM_LOG_ERROR;
	 }
      }
      else if (!strcmp(argv[i], "clear")) {
	 opt_args.startup = ST_CLEAR;
      }
      else if (!strcmp(argv[i], "save")) {
	 opt_args.startup = ST_SAVE;
      }
      else if (!strcmp(argv[i], "deactivated")) {
	 opt_args.startup = ST_DEACTIVATED;
      }
      else if (!strncmp(argv[i], "maintcmds=", 10)) {
         if(!strcmp(argv[i] + 10, "1")) {
            opt_args.enable_maint_cmds = true;
         } else if(!strcmp(argv[i] + 10, "0")) {
            opt_args.enable_maint_cmds = false;
         }
      }
      else if(!strncmp(argv[i], "hwinitpcr=", 10)) {
         char *pch = argv[i] + 10;
         unsigned int v1, v2;
         pch = strtok(pch, ",");
         while(pch != NULL) {
            if(!strcmp(pch, "all")) {
               //Set all
               opt_args.hwinitpcrs = VTPM_PCRALL;
            } else if(!strcmp(pch, "none")) {
               //Set none
               opt_args.hwinitpcrs = VTPM_PCRNONE;
            } else if(sscanf(pch, "%u", &v1) == 1) {
               //Set one
               if(v1 >= TPM_NUM_PCR) {
                  error("hwinitpcr error: Invalid PCR index %u", v1);
                  return -1;
               }
               opt_args.hwinitpcrs |= (1 << v1);
            } else if(sscanf(pch, "%u-%u", &v1, &v2) == 2) {
               //Set range
               if(v1 >= TPM_NUM_PCR) {
                  error("hwinitpcr error: Invalid PCR index %u", v1);
                  return -1;
               }
               if(v2 >= TPM_NUM_PCR) {
                  error("hwinitpcr error: Invalid PCR index %u", v1);
                  return -1;
               }
               if(v2 < v1) {
                  unsigned tp = v1;
                  v1 = v2;
                  v2 = tp;
               }
               for(unsigned int i = v1; i <= v2; ++i) {
                  opt_args.hwinitpcrs |= (1 << i);
               }
            } else {
               error("hwintipcr error: Invalid PCR specification : %s", pch);
               return -1;
            }
            pch = strtok(NULL, ",");
         }
      }
      else {
	 error("Invalid command line option `%s'", argv[i]);
      }

   }

   /* Check Errors and print results */
   switch(opt_args.startup) {
      case ST_CLEAR:
	 info("Startup mode is `clear'");
	 break;
      case ST_SAVE:
	 info("Startup mode is `save'");
	 break;
      case ST_DEACTIVATED:
	 info("Startup mode is `deactivated'");
	 break;
      default:
	 error("Invalid startup mode %d", opt_args.startup);
	 return -1;
   }

   if(opt_args.hwinitpcrs & (VTPM_PCRALL))
   {
      char pcrstr[1024];
      char* ptr = pcrstr;

      pcrstr[0] = '\0';
      info("The following PCRs will be initialized with values from the hardware TPM:");
      for(unsigned int i = 0; i < TPM_NUM_PCR; ++i) {
         if(opt_args.hwinitpcrs & (1 << i)) {
            ptr += sprintf(ptr, "%u, ", i);
         }
      }
      /* get rid of the last comma if any numbers were printed */
      *(ptr -2) = '\0';

      info("\t%s", pcrstr);
   } else {
      info("All PCRs initialized to default values");
   }

   if(!opt_args.enable_maint_cmds) {
      info("TPM Maintenance Commands disabled");
      badords[n_badords++] = TPM_ORD_CreateMaintenanceArchive;
      badords[n_badords++] = TPM_ORD_LoadMaintenanceArchive;
      badords[n_badords++] = TPM_ORD_KillMaintenanceFeature;
      badords[n_badords++] = TPM_ORD_LoadManuMaintPub;
      badords[n_badords++] = TPM_ORD_ReadManuMaintPub;
   } else {
      info("TPM Maintenance Commands enabled");
   }

   info("Log level set to %s", logstr);

   return 0;
}

void cleanup_opt_args(void) {
}

int main(int argc, char **argv)
{
   //FIXME: initializing blkfront without this sleep causes the domain to crash on boot
   sleep(2);

   /* Setup extern function pointers */
   tpm_extern_init = vtpm_extern_init_fake;
   tpm_extern_release = vtpm_extern_release_fake;
   tpm_malloc = malloc;
   tpm_free = free;
   tpm_log = vtpm_log;
   tpm_get_ticks = vtpm_get_ticks;
   tpm_get_extern_random_bytes = vtpm_get_extern_random_bytes;
   tpm_write_to_storage = vtpm_write_to_file;
   tpm_read_from_storage = vtpm_read_from_file;

   info("starting TPM Emulator (1.2.%d.%d-%d)", VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD);
   if(parse_cmd_line(argc, argv)) {
      error("Error parsing commandline\n");
      return -1;
   }

   /* Initialize devices */
   init_tpmback(NULL, NULL);
   if((tpmfront_dev = init_tpmfront(NULL)) == NULL) {
      error("Unable to initialize tpmfront device");
      goto abort_posttpmfront;
   }

   /* Seed the RNG with entropy from hardware TPM */
   if(init_random()) {
      error("Unable to initialize RNG");
      goto abort_postrng;
   }

   /* Initialize blkfront device */
   if(init_vtpmblk(tpmfront_dev)) {
      error("Unable to initialize Blkfront persistent storage");
      goto abort_postvtpmblk;
   }

   /* Run main loop */
   main_loop();

   /* Shutdown blkfront */
   shutdown_vtpmblk();
abort_postvtpmblk:
abort_postrng:

   /* Close devices */
   shutdown_tpmfront(tpmfront_dev);
abort_posttpmfront:
   shutdown_tpmback();

   cleanup_opt_args();

   return 0;
}
