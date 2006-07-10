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


#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>

#include "tcg.h"
#include "bsg.h"
#include "buffer.h"

static TPM_RESULT buffer_priv_realloc (buffer_t * buf, tpm_size_t newsize);

//
// buffer functions!
//

TPM_RESULT buffer_init (buffer_t * buf, tpm_size_t initsize, const BYTE* initval) {
  if (initsize == 0) {
    memset(buf, 0, sizeof(*buf));
    return TPM_SUCCESS;
  }
  
  
  buf->bytes = (BYTE*) malloc (initsize);
  if (buf->bytes == NULL) 
    return TPM_RESOURCES;
  
  buf->size = initsize;
  buf->alloc_size = initsize;
  
  if (initval)
    memcpy (buf->bytes, initval, initsize);
  
  buf->is_owner = TRUE;
  
  return TPM_SUCCESS;
}

TPM_RESULT buffer_init_convert (buffer_t * buf, tpm_size_t initsize, BYTE* initval) {
  
  buf->size = initsize;
  buf->alloc_size = initsize;
  buf->bytes = initval;
  
  buf->is_owner = TRUE;
  
  return TPM_SUCCESS;
}

TPM_RESULT buffer_init_copy (buffer_t * buf, const buffer_t * src) {
  TPM_RESULT status = buffer_init (buf, src->size, src->bytes);
  buf->is_owner = TRUE;
  
  return status;
}



// make an alias to a constant array
TPM_RESULT buffer_init_const (buffer_t * buf, tpm_size_t size, const BYTE* val) {
  // TODO: try to enforce the const things somehow!
  buf->bytes = (BYTE*) val;
  buf->size = size;
  buf->alloc_size = 0;        // this field is now unneeded
  
  buf->is_owner = FALSE;
  
  return TPM_SUCCESS;
}

// make an alias into buf, with given offset and length
// if len = 0, make the alias go to the end of buf
TPM_RESULT buffer_init_alias (buffer_t * buf, const buffer_t * b,
                              tpm_size_t offset, tpm_size_t len) {
  if (offset + len > b->size) {
    return TPM_NOSPACE;
  }
  
  buf->bytes = b->bytes + offset;
  buf->size = len > 0 ? len : b->size - offset;
  
  //VS/ buf->alloc_size = 0;
  if (len ==0)
    buf->alloc_size = b->alloc_size - offset;
  else 
    buf->alloc_size = MIN(b->alloc_size - offset, len);
  
        
  buf->is_owner = FALSE;
  
  return TPM_SUCCESS;
}

// make an alias buffer_t into bytestream, with given length
TPM_RESULT buffer_init_alias_convert (buffer_t * buf, tpm_size_t size, BYTE* val) {

  buf->size = size;
  buf->alloc_size = size;
  buf->bytes = val;

  buf->is_owner = FALSE;

  return TPM_SUCCESS;
}

 

// copy into the start of dest
TPM_RESULT buffer_copy (buffer_t * dest, const buffer_t* src)
{
  TPM_RESULT status = TPM_SUCCESS;
    
  if (dest->alloc_size < src->size) {  
    TPMTRYRETURN( buffer_priv_realloc (dest, src->size) );
  }
  
  memcpy (dest->bytes, src->bytes, src->size);
  dest->size = src->size;
  
  //VS/ dest->is_owner = TRUE;
  
 abort_egress:

  return status;
}



BOOL buffer_eq (const buffer_t * a, const buffer_t * b) {
  return (a->size == b->size && memcmp (a->bytes, b->bytes, a->size) == 0);
}


void buffer_memset (buffer_t * buf, BYTE b) {
  memset (buf->bytes, b, buf->size);
}


TPM_RESULT buffer_append_raw (buffer_t * buf, tpm_size_t len, const BYTE* bytes) {
  TPM_RESULT status = TPM_SUCCESS;
  
  if (buf->alloc_size < buf->size + len) {
    TPMTRYRETURN( buffer_priv_realloc (buf, buf->size + len) );
  }
  
  memcpy (buf->bytes + buf->size, bytes, len);
  
  buf->size += len;
  
  goto egress;
  
 abort_egress:
  
 egress:
  
  return status;
}

tpm_size_t buffer_len (const buffer_t* buf) {
  return buf->size;
}

TPM_RESULT buffer_free (buffer_t * buf) {
  if (buf && buf->is_owner && buf->bytes != NULL) {
    free (buf->bytes);
    buf->bytes = NULL;
    buf->size = buf->alloc_size = 0;
   
  }
  
  return TPM_SUCCESS;
}

TPM_RESULT buffer_priv_realloc (buffer_t * buf, tpm_size_t newsize) {
  
  // we want to realloc to twice the size, or the new size, whichever
  // bigger
  
  BYTE * tmpbuf = NULL;
  
  newsize = MAX (buf->alloc_size * 2, newsize);
  
  tmpbuf = (BYTE*) realloc (buf->bytes, newsize);
  if (tmpbuf == NULL) 
    return TPM_SIZE;
  
  
  buf->bytes = tmpbuf;
  buf->alloc_size = newsize;
  
  return TPM_SUCCESS;
}
