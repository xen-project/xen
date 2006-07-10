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

#ifndef __VTPM_BUFFER_H__
#define __VTPM_BUFFER_H__

#include <stddef.h>             // for pointer NULL
#include "tcg.h"

typedef UINT32 tpm_size_t;

// first version, probably will be expanded...

#define NULL_BUF {0,0,0,0}

typedef struct {
  // private!!
  tpm_size_t size, alloc_size;
  BYTE * bytes;
  
  BOOL is_owner;              // do we own this buffer, and need to free it?
} buffer_t;

// allocate the buffer if initsize > 0, copying over initval if provided
TPM_RESULT buffer_init (buffer_t * buf,
                        tpm_size_t initsize,
                        const BYTE* initval);

// Create a new buffer from a BYTE *. Use buffer_free to destroy original BYTE *
TPM_RESULT buffer_init_convert (buffer_t * buf, 
                                tpm_size_t initsize, 
                                BYTE* initval);

// make an alias to a constant array, no copying
TPM_RESULT buffer_init_const (buffer_t * buf, tpm_size_t size, const BYTE* val);

// make an alias into buf, with given offset and length
// if len = 0, make the alias go to the end of buf
TPM_RESULT buffer_init_alias (buffer_t * buf, const buffer_t * b,
                              tpm_size_t offset, tpm_size_t);

// make an alias buffer into a bytestream
TPM_RESULT buffer_init_alias_convert (buffer_t * buf, 
                                      tpm_size_t size, BYTE* val);

// "copy constructor"
TPM_RESULT buffer_init_copy (buffer_t * buf, const buffer_t * src);


// copy into the start of a
TPM_RESULT buffer_copy (buffer_t * dest, const buffer_t* src);

// are they equal?
BOOL buffer_eq (const buffer_t * a, const buffer_t * b);

// set the buffer to a constant byte
void buffer_memset (buffer_t * buf, BYTE b);

tpm_size_t buffer_len (const buffer_t* buf);

TPM_RESULT buffer_free (buffer_t * buf);

TPM_RESULT buffer_append_raw (buffer_t * buf, tpm_size_t len, const BYTE* bytes);

#endif // _TOOLS_H_
