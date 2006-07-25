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
static int g_tx_fd = -1;              // the fd to the TPM

#ifndef DUMMY_TPM
 #define TPM_TX_FNAME "/dev/tpm0"
 static int *g_rx_fdp = &g_tx_fd;
#else
 #define TPM_TX_FNAME "/var/tpm/tpm_in.fifo"
 #define TPM_RX_FNAME "/var/tpm/tpm_out.fifo"
 static int g_rx_fd = -1;
 static int *g_rx_fdp = &g_rx_fd;              // the fd to the TPM
#endif

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
  
  // send the request
  size = write (g_tx_fd, in, insize);
  if (size < 0) {
    vtpmlogerror(VTPM_LOG_TXDATA, "write() failed");
    ERRORDIE (TPM_IOERROR);
  }
  else if ((TDDL_UINT32) size < insize) {
    vtpmlogerror(VTPM_LOG_TXDATA, "Wrote %d instead of %d bytes!\n", (int) size, insize);
    // ... ?
  }

  // read the response
  size = read (*g_rx_fdp, out, TCPA_MAX_BUFFER_LENGTH);
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
  
  if (g_TDDL_open)
    return TPM_FAIL;

#ifdef DUMMY_TPM  
  *g_rx_fdp = open (TPM_RX_FNAME, O_RDWR);
#endif

  g_tx_fd = open (TPM_TX_FNAME, O_RDWR);
  if (g_tx_fd < 0) {
    vtpmlogerror(VTPM_LOG_TXDATA, "TPM open failed");
    return TPM_IOERROR;
  }
  
  g_TDDL_open = 1;
  
  return status;
}

void TDDL_Close() {
  if (! g_TDDL_open)
        return;

  if (g_tx_fd>= 0) {
    if (close(g_tx_fd) < 0) 
      vtpmlogerror(VTPM_LOG_TXDATA, "closeing tpm failed");
    g_tx_fd = -1;
  }
    
  if (*g_rx_fdp>= 0) {
    if (close(*g_rx_fdp) < 0) 
      vtpmlogerror(VTPM_LOG_TXDATA, "closeing tpm failed");
    *g_rx_fdp = -1;
  }

  g_TDDL_open = 0;
  
}
