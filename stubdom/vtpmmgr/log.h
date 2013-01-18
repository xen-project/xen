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

#ifndef __VTPM_LOG_H__
#define __VTPM_LOG_H__

#include <stdint.h>             // for uint32_t
#include <stddef.h>             // for pointer NULL
#include <stdio.h>
#include "tcg.h"

// =========================== LOGGING ==============================

// the logging module numbers
#define VTPM_LOG_TPM         1
#define VTPM_LOG_TPM_DEEP    2
#define VTPM_LOG_VTPM        3
#define VTPM_LOG_VTPM_DEEP   4
#define VTPM_LOG_TXDATA      5

extern char *module_names[];

// Default to standard logging
#ifndef LOGGING_MODULES
#define LOGGING_MODULES (BITMASK(VTPM_LOG_VTPM)|BITMASK(VTPM_LOG_TPM))
#endif

// bit-access macros
#define BITMASK(idx)      ( 1U << (idx) )
#define GETBIT(num,idx)   ( ((num) & BITMASK(idx)) >> idx )
#define SETBIT(num,idx)   (num) |= BITMASK(idx)
#define CLEARBIT(num,idx) (num) &= ( ~ BITMASK(idx) )

#define vtpmloginfo(module, fmt, args...) \
  if (GETBIT (LOGGING_MODULES, module) == 1) {				\
    fprintf (stdout, "INFO[%s]: " fmt, module_names[module], ##args); \
  }

#define vtpmloginfomore(module, fmt, args...) \
  if (GETBIT (LOGGING_MODULES, module) == 1) {			      \
    fprintf (stdout, fmt,##args);				      \
  }

#define vtpmlogerror(module, fmt, args...) \
  fprintf (stderr, "ERROR[%s]: " fmt, module_names[module], ##args);

//typedef UINT32 tpm_size_t;

// helper function for the error codes:
const char* tpm_get_error_name (TPM_RESULT code);

#endif // _VTPM_LOG_H_
