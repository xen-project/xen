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
#include <mini-os/tpmback.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"

#include "vtpmmgr.h"
#include "tcg.h"


void main_loop(void) {
   tpmcmd_t* tpmcmd;
   uint8_t respbuf[TCPA_MAX_BUFFER_LENGTH];

   while(1) {
      /* Wait for requests from a vtpm */
      vtpmloginfo(VTPM_LOG_VTPM, "Waiting for commands from vTPM's:\n");
      if((tpmcmd = tpmback_req_any()) == NULL) {
         vtpmlogerror(VTPM_LOG_VTPM, "NULL tpmcmd\n");
         continue;
      }

      tpmcmd->resp = respbuf;

      /* Process the command */
      vtpmmgr_handle_cmd(tpmcmd->opaque, tpmcmd);

      /* Send response */
      tpmback_resp(tpmcmd);
   }
}

int main(int argc, char** argv)
{
   int rc = 0;
   sleep(2);
   vtpmloginfo(VTPM_LOG_VTPM, "Starting vTPM manager domain\n");

   /* Initialize the vtpm manager */
   if(vtpmmgr_init(argc, argv) != TPM_SUCCESS) {
      vtpmlogerror(VTPM_LOG_VTPM, "Unable to initialize vtpmmgr domain!\n");
      rc = -1;
      goto exit;
   }

   main_loop();

   vtpmloginfo(VTPM_LOG_VTPM, "vTPM Manager shutting down...\n");

   vtpmmgr_shutdown();

exit:
   return rc;

}
