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
// vtpm_ipc.h Header for interprocess communication between VTPM manager
// and Guests or VTPMs
//
// ===================================================================

#ifndef __VTPM_IO_H__
#define __VTPM_IO_H__

#include "tcg.h"

#define VTPM_IPC_CLOSED -1

// Represents an (somewhat) abstracted io handle.
typedef struct vtpm_ipc_handle_t {
  int fh;              // IO handle.
  int flags;           // Flags for opening. This may need to become
                       // a void *, but for now files use an int.
  char *name;          // Names for debugging as well as filenames
                       // for file-based io.
} vtpm_ipc_handle_t;


int vtpm_ipc_init(vtpm_ipc_handle_t *ioh, char* name, int flags, BOOL create);

// Create the file that needs opening. Used only for FIFOs
// FYI: This may cause problems in other file IO schemes. We'll see.
int vtpm_ipc_create(vtpm_ipc_handle_t *ioh);

// Read size bytes. If FH isn't open, open it.
int vtpm_ipc_read(vtpm_ipc_handle_t *ioh, vtpm_ipc_handle_t *alt_ioh, BYTE *bytes, UINT32 size);

// Write size bytes. If FH isn't open, open it.
int vtpm_ipc_write(vtpm_ipc_handle_t *ioh, vtpm_ipc_handle_t *alt_ioh, BYTE *bytes, UINT32 size);

// Mark file as closed and try and close it. Errors not reported.
void vtpm_ipc_close(vtpm_ipc_handle_t *ioh);

#endif
