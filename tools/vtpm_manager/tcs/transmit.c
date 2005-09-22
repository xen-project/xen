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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include "tcg.h"
#include "buffer.h"
#include "log.h"
#include "tpmddl.h"

// flag to track whether TDDL has been opened
static int g_TDDL_open = 0;
static int g_fd = -1;              // the fd to the TPM

TPM_RESULT
TDDL_TransmitData( TDDL_BYTE* in,
		   TDDL_UINT32 insize,
		   TDDL_BYTE* out,
		   TDDL_UINT32* outsize) {
  TPM_RESULT status = TPM_SUCCESS;
  TDDL_UINT32 i;
  
  vtpmloginfo(VTPM_LOG_TXDATA, "Sending buffer = 0x");
  for(i = 0 ; i < insize ; i++) 
    vtpmloginfomore(VTPM_LOG_TXDATA, "%2.2x ", in[i]);

  vtpmloginfomore(VTPM_LOG_TXDATA, "\n");
  
  ssize_t size = 0;
  int fd = g_fd;
  
  // send the request
  size = write (fd, in, insize);
  if (size < 0) {
    vtpmlogerror(VTPM_LOG_TXDATA, "write() failed");
    ERRORDIE (TPM_IOERROR);
  }
  else if ((TDDL_UINT32) size < insize) {
    vtpmlogerror(VTPM_LOG_TXDATA, "Wrote %d instead of %d bytes!\n", (int) size, insize);
    // ... ?
  }

  // read the response
  size = read (fd, out, TCPA_MAX_BUFFER_LENGTH);
  if (size < 0) {
    vtpmlogerror(VTPM_LOG_TXDATA, "read() failed");
    ERRORDIE (TPM_IOERROR);
  }
  
  vtpmloginfo(VTPM_LOG_TXDATA, "Receiving buffer = 0x");
  for(i = 0 ; i < size ; i++) 
    vtpmloginfomore(VTPM_LOG_TXDATA, "%2.2x ", out[i]);

  vtpmloginfomore(VTPM_LOG_TXDATA, "\n");

  *outsize = size;
  // close connection
  goto egress;
  
 abort_egress:
 egress:
  return status;
}

TPM_RESULT TDDL_Open() {
  
  TDDL_RESULT status = TDDL_SUCCESS;
  int fd = -1;
  
  if (g_TDDL_open)
    return TPM_FAIL;
  
  fd = open ("/dev/tpm0", O_RDWR);
  if (fd < 0) {
    vtpmlogerror(VTPM_LOG_TXDATA, "TPM open failed");
    return TPM_IOERROR;
  }
  
  g_fd = fd;
  g_TDDL_open = 1;
  
  return status;
}

void TDDL_Close() {
  if (! g_TDDL_open)
        return;

  if (g_fd>= 0) {
    if (close(g_fd) < 0) 
      vtpmlogerror(VTPM_LOG_TXDATA, "closeing tpm failed");
    
    g_fd = -1;
  }
    
  g_TDDL_open = 0;
  
}
