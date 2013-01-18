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

#ifndef VTPM_H
#define VTPM_H

#include <stdbool.h>

/* For testing */
#define VERS_CMD "\x00\xC1\x00\x00\x00\x16\x00\x00\x00\x65\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x01\x03"
#define VERS_CMD_LEN 22

/* Global commandline options */
struct Opt_args {
   enum StartUp {
      ST_CLEAR = 1,
      ST_SAVE = 2,
      ST_DEACTIVATED = 3
   } startup;
   unsigned long hwinitpcrs;
   int loglevel;
   uint32_t tpmconf;
   bool enable_maint_cmds;
};
extern struct Opt_args opt_args;

#endif
