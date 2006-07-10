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
//
// vtpm_ipc.c Implements ipc routines using file io. This file can
// be replaced with other ipc types.
//
// ===================================================================

#include <sys/stat.h>
#include "vtpm_ipc.h"
#include "vtpmpriv.h"
#include "log.h"

int vtpm_ipc_init(vtpm_ipc_handle_t *ipc_h, char* name, int flags, BOOL create) {
  ipc_h->name = name;
  ipc_h->flags = flags;
  ipc_h->fh = VTPM_IPC_CLOSED;

  if (create)
    return(vtpm_ipc_create(ipc_h));
  else
    return 0;
}

// Create the file that needs opening. Used only for FIFOs
// FYI: This may cause problems in other file IO schemes. We'll see.
int vtpm_ipc_create(vtpm_ipc_handle_t *ipc_h) {
  int fh;
  struct stat file_info;

  if ((!ipc_h) || (!ipc_h->name))
    return -1;

  if ( stat(ipc_h->name, &file_info) == -1) {
    if ( mkfifo(ipc_h->name, S_IWUSR | S_IRUSR ) ) {
      vtpmlogerror(VTPM_LOG_VTPM, "Failed to create fifo %s.\n", ipc_h->name);
      return -1;
    }
  }

  ipc_h->fh = VTPM_IPC_CLOSED;

  return 0;
}


// Read size bytes. If FH isn't open, open it.
int vtpm_ipc_read(vtpm_ipc_handle_t *ipc_h, vtpm_ipc_handle_t *alt_ipc_h, BYTE *bytes, UINT32 size){
  vtpm_ipc_handle_t *my_ipc_h;
  int result;
  
  if (ipc_h) {
    my_ipc_h = ipc_h;
  } else {
    my_ipc_h = alt_ipc_h;
  }
  
  if (my_ipc_h->fh == VTPM_IPC_CLOSED) {   
    my_ipc_h->fh = open(my_ipc_h->name, my_ipc_h->flags);
  }

  if ( my_ipc_h->fh == VTPM_IPC_CLOSED ) {
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM ERROR: Can't open %s for reading.\n", my_ipc_h->name);
    return -1;
  }

  result = read(my_ipc_h->fh, bytes, size);
  if (result < 0) {
    my_ipc_h->fh = VTPM_IPC_CLOSED;
  }

  return (result);
}

// Write size bytes. If FH isn't open, open it.
int vtpm_ipc_write(vtpm_ipc_handle_t *ipc_h, vtpm_ipc_handle_t *alt_ipc_h, BYTE *bytes, UINT32 size) {
  vtpm_ipc_handle_t *my_ipc_h;
  int result;

  if (ipc_h) {
    my_ipc_h = ipc_h;
  } else {
    my_ipc_h = alt_ipc_h;
  }

  if (my_ipc_h->fh == VTPM_IPC_CLOSED) {
    my_ipc_h->fh = open(my_ipc_h->name, my_ipc_h->flags);
  }

  if ( my_ipc_h->fh == VTPM_IPC_CLOSED ) {
    vtpmlogerror(VTPM_LOG_VTPM, "VTPM ERROR: Can't open %s for writing.\n", my_ipc_h->name);
    return -1;
  }

  result = write(my_ipc_h->fh, bytes, size);
  if (result < 0) {
    my_ipc_h->fh = VTPM_IPC_CLOSED;
  }

  return (result);
}

// Mark file as closed and try and close it. Errors not reported.
void vtpm_ipc_close(vtpm_ipc_handle_t *ipc_h) {

  if (ipc_h) {
    close(ipc_h->fh);
    ipc_h->fh = VTPM_IPC_CLOSED;
  }

}
