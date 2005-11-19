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
// bsg.cpp
// 
//  This file will handle all the TPM Byte Stream functions
// 
// ==================================================================

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <malloc.h>
#include "tcg.h"
#include "crypto.h"
#include "bsg.h"
#include "log.h"

static int g_log_recursion_level = 0;

// a largest buffer size. if we get a buf size bigger than this when unpacking,
// will complain!
#define BSG_MAX_BUF_SIZE (1<<18)

#define bsglog(fmt, ...) do { \
    int __i; \
    for (__i=0; __i < g_log_recursion_level; __i++) {		     \
      vtpmloginfomore (VTPM_LOG_BSG, "%s", "  ");			     \
    }								       \
    vtpmloginfomore (VTPM_LOG_BSG, fmt, __VA_ARGS__);			       \
  } while (0)


// FIXME:  trigger the selfcheck--need to use glibc hook to do this
//BOOL dummy1 = BSG_static_selfcheck();


// Interpretting Types
// -------------------
// 
// Incoming Types are composed of two parts {format, info} squished into a
// BSG_UINT32.  The first 4 bits is a format spec indicating what type of
// data it is.  If the first 4 bits are zero the info corresponds to a value in
// BSG_s_fmt[]. This is a structure whose composition is described in
// BSG_s_fmt[]. If the value is non-zero, info corresponds to the size of the
// data (in bytes) being passed in. For example a UINT32 being passed in would
// have a format of (__FMT_CONST | 4). If both, the format and info are zero,
// this is interpretted as the end of the structure, and the result is returned.

// these flags are mutually exclusive, so I'll just make them
// format values which indicate the semantics of the 'info' part and the source
// data. The above description has been accordingly adjusted.

// format values for determining what type of data the incoming type is
// it's a 4 bit value, occupying the high 4 bits
#define __FMT_CONST (1UL << 28) // Constant sized value
#define __FMT_DATA  (2UL << 28) // Believed to be raw data NOT {size,data}
#define __FMT_SIZE  (3UL << 28) // A size. Used in FMT_SIZE??_DATA.
#define __FMT_HSIZE (4UL << 28) // A number of handles
#define __FMT_PACKED (5UL << 28) // 'info' is unused; the source data consists
                                 // of {size32, data} but we're to pack only the
                                 // data as that is already packed, and so
                                 // can/must be unpacked without
                                 // explicitly reading it size

#define __FMT_MASK  0x0FFFFFFFUL // this masks out the 4-bit format
#define __FMT_MASK_SIZE(type)   ((type) & __FMT_MASK)
#define __FMT_MASK_FORMAT(type) ((type) & (~__FMT_MASK))

// constant (8/16/32-bits)
#define FMT_U8 (__FMT_CONST | 1UL)
#define FMT_U16 (__FMT_CONST | 2UL)
#define FMT_U32 (__FMT_CONST | 4UL)

// const with a compiler-computed size
#define FMT_SIZEOF(type) (__FMT_CONST | sizeof(type))

// other data (size bytes) 
// Used primarily for DIGESTS -> FMT_DATA(20)
#define FMT_DATA(size) (__FMT_DATA | ((BSG_UINT32) (size) & __FMT_MASK))

// 16/32-bit size followed by N bytes of data
#define FMT_SIZE16_DATA (__FMT_SIZE | 2UL)
#define FMT_SIZE32_DATA (__FMT_SIZE | 4UL)

// 16-bit size followed by N key handles
#define FMT_SIZE16_HANDLES (__FMT_HSIZE | 2UL)

#define DIGEST_SIZE 20 
typedef BSG_UINT32 BSG_HANDLE;

// TCPA_AUTH has 11 fields!
#define MAX_FIELDS 11
typedef struct BSG_Format
{
  BSG_Type type;
  const char* name;
  BSG_UINT32 fields[MAX_FIELDS + 1];
} BSG_Format;

/*
 * TCPA structure data formats
 */
// this has to be manually kept in sync with the
// Type enum!! the static_selfcheck() function should be used regularly!
static BSG_Format s_fmt[] =
{
  {BSG_TYPE_UINT32, "BSG_TYPE_UINT32", {FMT_U32, 0}},
  {BSG_TYPE_UINT16, "BSG_TYPE_UINT16", {FMT_U16, 0}},
  {BSG_TYPE_BYTE, "BSG_TYPE_BYTE", {FMT_U8, 0}},
  {BSG_TYPE_BOOL, "BSG_TYPE_BOOL", {FMT_U8, 0}},
  {BSG_TPM_SIZE32_DATA, "BSG_TPM_SIZE32_DATA", {FMT_SIZE32_DATA, 0}},
  {BSG_TPM_TAG, "BSG_TPM_TAG", {FMT_SIZEOF(TPM_TAG), 0}},
  {BSG_TPM_HANDLE, "BSG_TPM_HANDLE", {FMT_SIZEOF(TPM_HANDLE), 0}},
  {BSG_TPM_RESULT, "BSG_TPM_RESULT", {FMT_SIZEOF(TPM_RESULT), 0}},
  {BSG_TPM_RESOURCE_TYPE, "BSG_TPM_RESOURCE_TYPE", {FMT_SIZEOF(TPM_RESOURCE_TYPE), 0}},
  {BSG_TPM_COMMAND_CODE, "BSG_TPM_COMMAND_CODE", {FMT_U32, 0}},
  {BSG_TPM_AUTH_DATA_USAGE, "BSG_TPM_AUTH_DATA_USAGE", {FMT_U8, 0}},
  {BSG_TPM_ALGORITHM_ID, "BSG_TPM_ALGORITHM_ID", {FMT_U32, 0}},
  {BSG_TPM_PROTOCOL_ID, "BSG_TPM_PROTOCOL_ID", {FMT_SIZEOF(TPM_PROTOCOL_ID), 0}},
  {BSG_TPM_KEY_USAGE, "BSG_TPM_KEY_USAGE", {FMT_U16, 0}},
  {BSG_TPM_ENC_SCHEME, "BSG_TPM_ENC_SCHEME", {FMT_U16, 0}},
  {BSG_TPM_SIG_SCHEME, "BSG_TPM_SIG_SCHEME", {FMT_U16, 0}},
  {BSG_TPM_MIGRATE_SCHEME, "BSG_TPM_MIGRATE_SCHEME", {FMT_U16, 0}},
  {BSG_TPM_KEY_FLAGS, "BSG_TPM_KEY_FLAGS", {FMT_U32, 0}},
    
  {BSG_TPM_AUTHDATA, "BSG_TPM_AUTHDATA", {FMT_DATA(DIGEST_SIZE), 0}},
  {BSG_TPM_SECRET, "BSG_TPM_SECRET", {BSG_TPM_AUTHDATA, 0}},
  {BSG_TPM_ENCAUTH, "BSG_TPM_ENCAUTH", {BSG_TPM_AUTHDATA, 0}},
  {BSG_TPM_PAYLOAD_TYPE, "BSG_TPM_PAYLOAD_TYPE", {FMT_SIZEOF(TPM_PAYLOAD_TYPE), 0}},
  
  {BSG_TPM_VERSION, "BSG_TPM_VERSION", {FMT_DATA(4), 0}}, // vers 1.2
  {BSG_TPM_DIGEST, "BSG_TPM_DIGEST", {FMT_DATA(DIGEST_SIZE), 0}},
  {BSG_TPM_COMPOSITE_HASH, "BSG_TPM_COMPOSITE_HASH", {BSG_TPM_DIGEST, 0}},
  {BSG_TPM_CHOSENID_HASH, "BSG_TPM_CHOSENID_HASH", {BSG_TPM_DIGEST, 0}},
  
  {BSG_TPM_NONCE, "BSG_TPM_NONCE", {FMT_DATA(DIGEST_SIZE), 0}},
  {BSG_TPM_KEY_HANDLE, "BSG_TPM_KEY_HANDLE", {FMT_SIZEOF(TPM_KEY_HANDLE), 0}},
  {BSG_TPM_KEY_HANDLE_LIST, "BSG_TPM_KEY_HANDLE_LIST",
   {FMT_SIZE16_HANDLES, 0}},
  
  {BSG_TPM_KEY_PARMS, "BSG_TPM_KEY_PARMS", {
      BSG_TPM_ALGORITHM_ID,
      BSG_TPM_ENC_SCHEME,
      BSG_TPM_SIG_SCHEME,
      FMT_SIZE32_DATA,
      0}},
  {BSG_TPM_RSA_KEY_PARMS, "BSG_TPM_RSA_KEY_PARMS", {
      FMT_U32, FMT_U32, FMT_SIZE32_DATA, 0}},
  {BSG_TPM_STORE_PUBKEY, "BSG_TPM_STORE_PUBKEY", {FMT_SIZE32_DATA, 0}},
  {BSG_TPM_PUBKEY, "BSG_TPM_PUBKEY", {BSG_TPM_KEY_PARMS, BSG_TPM_STORE_PUBKEY, 0}},
  {BSG_TPM_KEY, "BSG_TPM_KEY", {
      BSG_TPM_VERSION,
      BSG_TPM_KEY_USAGE,
      BSG_TPM_KEY_FLAGS,
      BSG_TPM_AUTH_DATA_USAGE,
      BSG_TPM_KEY_PARMS,
      FMT_SIZE32_DATA,        // the PCR_INFO
      BSG_TPM_STORE_PUBKEY,
      FMT_SIZE32_DATA,        // the encrypted part
      0}},
  
  {BSG_TPM_MIGRATIONKEYAUTH, "BSG_TPM_MIGRATIONKEYAUTH", {
      BSG_TPM_PUBKEY,
      BSG_TPM_MIGRATE_SCHEME,
      BSG_TPM_DIGEST, 0}},
  
  {BSG_TCPA_AUDIT_EVENT, "TCPA_AUDIT_EVENT", {
      BSG_TPM_COMMAND_CODE,
      BSG_TPM_RESULT, 0 }},
  
  {BSG_TCPA_EVENT_CERT, "TCPA_EVENT_CERT", {
      BSG_TPM_DIGEST,
      BSG_TPM_DIGEST,
      FMT_DATA(2),
      FMT_SIZE32_DATA, 0}},
  
  {BSG_TPM_PCR_SELECTION, "BSG_TPM_PCR_SELECTION", {FMT_SIZE16_DATA, 0} },
  {BSG_TPM_PCR_COMPOSITE, "BSG_TPM_PCR_COMPOSITE", { BSG_TPM_PCR_SELECTION,
						     FMT_SIZE32_DATA,
						     0} },

  {BSG_TPM_PCR_INFO, "BSG_TPM_PCR_INFO", { BSG_TPM_PCR_SELECTION,
					   BSG_TPM_COMPOSITE_HASH, 
					   BSG_TPM_COMPOSITE_HASH,
					   0} },
  
  
  {BSG_TPM_STORED_DATA, "BSG_TPM_STORED_DATA", {
      BSG_TPM_VERSION,
      FMT_SIZE32_DATA,
      FMT_SIZE32_DATA,
      0}},
  {BSG_TPM_SYMMETRIC_KEY, "BSG_TPM_SYMMETRIC_KEY", {
      BSG_TPM_ALGORITHM_ID,
      BSG_TPM_ENC_SCHEME,
      FMT_SIZE16_DATA,
      0}},
  {BSG_TPM_STORE_PRIVKEY, "BSG_TPM_STORE_PRIVKEY", {FMT_SIZE32_DATA, 0}},
  {BSG_TPM_STORE_ASYMKEY, "BSG_TPM_STORE_ASYMKEY", {
      BSG_TPM_PAYLOAD_TYPE,
      BSG_TPM_SECRET,
      BSG_TPM_SECRET,
      BSG_TPM_DIGEST,
      BSG_TPM_STORE_PRIVKEY,
      0}},
  {BSG_TPM_MIGRATE_ASYMKEY, "BSG_TPM_MIGRATE_ASYMKEY", {
      BSG_TPM_PAYLOAD_TYPE,
      BSG_TPM_SECRET,
      BSG_TPM_DIGEST,
      FMT_U32,
      BSG_TPM_STORE_PRIVKEY,
      0}},
  
  {BSG_TPM_QUOTE_INFO, "BSG_TPM_QUOTE_INFO", {
      BSG_TPM_VERSION,
      FMT_DATA(4),
      BSG_TPM_COMPOSITE_HASH,
      BSG_TPM_NONCE,
      0}},
  
  {BSG_TPM_IDENTITY_CONTENTS, "BSG_TPM_IDENTITY_CONTENTS", {
      BSG_TPM_VERSION,
      FMT_U32,
      BSG_TPM_CHOSENID_HASH,
      BSG_TPM_PUBKEY,
      0}},
  
  {BSG_TPM_PCRVALUE, "BSG_TPM_PCRVALUE", {FMT_DATA(DIGEST_SIZE), 0}},
  
  {BSG_TCPA_PCR_FLAGS, "TCPA_PCR_FLAGS", {
      FMT_U8,
      FMT_U8,
      0}},
  
  {BSG_TCS_AUTH, "TCS_AUTH", {
      BSG_TYPE_UINT32, 
      BSG_TPM_NONCE, 
      BSG_TPM_NONCE, 
      BSG_TYPE_BOOL, 
      BSG_TPM_AUTHDATA, 
      0}},
  
  {BSG_TPM_KEY_NONSENSITIVE, "BSG_TPM_KEY_NONSENSITIVE", {
      BSG_TPM_VERSION,
      BSG_TPM_KEY_USAGE,
      BSG_TPM_KEY_FLAGS,
      BSG_TPM_AUTH_DATA_USAGE,
      BSG_TPM_KEY_PARMS,
      FMT_SIZE32_DATA,
      BSG_TPM_STORE_PUBKEY,
      0}},
  
  {BSG_PACKED, "BSG_PACKED", {
      __FMT_PACKED,
      0 }},
  
  {BSG_TYPE_MAX, "", {0}},
};


static const BSG_Format* find_format (BSG_Type t) {
  BSG_Format * f = s_fmt;
  
  if (t >= BSG_TYPE_MAX) {
    return NULL;
  }
  
  // WARNING: this depends on the enum and s_fmt[] array being in sync! make
  // sure to run the static_selfcheck() to make sure
  f = s_fmt + (t - BSG_TYPE_FIRST);
  
  return f;
}

//
// a consistency-checking routine which can be run at compile time
// (ie. immediately after compilation)
//
// tasks:
// - verify that s_fmt has one entry per Type t, and that entry is at s_fmt[t]
//
// conditions:
// - need that s_fmt[0] is the first type listed in the Type enum! ie the first
//   Type has value 0, not 1
//
// FIXME: should have a function be passed in here which is called if the test
// fails. Then the caller can decide what to do: abort, notify, whatever
// 
BOOL BSG_static_selfcheck ()
{
  int i;

  for (i=BSG_TYPE_FIRST; i <= BSG_TYPE_MAX; i++) {
    if (s_fmt[i - BSG_TYPE_FIRST].type != i) {
      bsglog ("%s\n", "BSG: static_selfcheck failed!\n");
      bsglog ("failure at %i, allegedly %s\n",
	      i, s_fmt[i - BSG_TYPE_FIRST].name);
      abort();
      return FALSE;
    }
  }
  
  bsglog ("%s\n", "BSG: static_selfcheck success!");
  return TRUE;
}


/**
 * Flatten a TCPA structure into a buffer in big-endian format
 * @type: TCPA structure type
 * @src: (IN) TCPA structure (OUT) end of TCPA structure
 * @dst: (OUT) flattened data
 * Returns: Flattened size or -1 for unknown types
 */
// make it so that it can just run through the whole process and return
// the packed size, without packing anything. this will be done if dst is NULL.
static int BSG_Pack_private(BSG_Type type, const BSG_BYTE** src, BSG_BYTE* dst)
{
  // check incoming parameters
  if (*src == NULL)
    return 0;
  
  const BSG_BYTE* s = *src;
  BSG_BYTE* d = dst;
  
  BSG_UINT32 size   = __FMT_MASK_SIZE(type);
  BSG_UINT32 format = __FMT_MASK_FORMAT(type);
  
  if (format == __FMT_CONST) // We are dealing with a fixed length value eg. UINT32
    {
      BSG_UINT32 val = 0;
      switch (size) {
      case 1: val = * (BYTE*) s; break;
      case 2: val = * (unsigned short*) s; break;
      case 4: val = * (BSG_UINT32*) s; break;
      }
      if (dst)
	BSG_PackConst(val, size, d);

      s += size;
      d += size;
    } else if (format == __FMT_DATA) { // We are dealing with raw data. Not sure when
    // this is used.
    
      if (dst) {
        bsglog ("BSG: __FMT_DATA size %d, src %p, dst %p\n", size, s, d);
        memcpy(d, s, size);
      }

      s += size;
      d += size;
  } else if (format == __FMT_SIZE || format == __FMT_HSIZE) { // It's a size, followed by that much data or handles
    
    BSG_UINT32 psize = 0;
    switch (size) {
    case 1: psize = * (BYTE*) s; break;
    case 2: psize = * (unsigned short*) s; break;
    case 4: psize = * (BSG_UINT32*) s; break;
    }
        
    if (dst)
      BSG_PackConst(psize, size, d);

    s += size;
    d += size;
    
    // now 's' points to an address, so cast it to BSG_BYTE**
    const BSG_BYTE* pdata = * ((BSG_BYTE**) s);
    s += sizeof(BSG_BYTE*);
    
    if (format == __FMT_HSIZE) {// This is a list of psize Handles
      if (dst) {
	BSG_HANDLE* d2 = (BSG_HANDLE*) d;
	BSG_HANDLE* p2 = (BSG_HANDLE*) pdata;
	BSG_UINT32 i;
	for (i = 0; i < psize; i++) 
	  d2[i] = BSG_UnpackConst((BSG_BYTE*)(p2 + i), 4);
	
      }
      d += psize * sizeof(BSG_HANDLE);
    } else {// If it's not psize handles, it's psize data.
      if (psize > 0) {
	if (dst) {
	  bsglog ("BSG: __FMT_SIZE, size=%d, src=%p, dst=%p\n",
		  psize, pdata, d);
	  memcpy(d, pdata, psize);
	}
      }
      d += psize;
    }
  } else if (format == __FMT_PACKED) {
    // the source buffer is a pack_constbuf_t, which has a size and a
    // pointer. just copy the buffer value, the size is not included in the
    // output stream.
    pack_constbuf_t * buf = (pack_constbuf_t*) s;
    
    if (dst) {
      bsglog ("BSG: __FMT_PACKED, size=%d, src=%p, dst=%p\n",
	      buf->size, buf->data, d);
      memcpy(d, buf->data, buf->size);
    }
        
    s += buf->size;
    d += buf->size;
  } else if (format == 0) {// No flags are set. This is a structure & it should
                          // be looked up in the bsg_s_fmt[]
    
    const BSG_Format* x = find_format (type);
    if (x == NULL) {
      vtpmloginfo(VTPM_LOG_BSG, "BSG_Pack: cannot find type %d\n", type);
      return -1;
    }
    
    if (dst)
      bsglog ("BSG_Pack type %s\n", x->name);
    
    
    // iterate through the fields
    const BSG_UINT32* f = x->fields;
    for (; *f; f++) {
      int fsize;
      
      g_log_recursion_level++;
      fsize = BSG_Pack_private((BSG_Type) *f, &s, dst ? d : NULL);
      g_log_recursion_level--;
      
      if (fsize <= 0)
	return fsize;
      
      d += fsize;
    }
  } else {
    vtpmlogerror(VTPM_LOG_BSG, "BSG_Pack(): Unknown format %d\n", format);
    return -1;
  }
  
  *src = s;
  return (d - dst);
}

/**
 * Unflatten a TCPA structure from a buffer in big-endian format
 * @type: TCPA structure type
 * @src: flattened data
 * @dst: (IN) TCPA structure (OUT) end of TCPA structure
 * Returns: Flattened size
 * Note: Returns flattened size NOT the unpacked structure size
 */
static int BSG_Unpack_private(BSG_Type type, const BSG_BYTE* src, BSG_BYTE** dst) {
  // check incoming parameters
  if (src == NULL)
    return 0;
  
  
  const BSG_BYTE* s = src;
  BSG_BYTE* d = dst ? *dst:NULL;
  if (dst && !d)
    dst = NULL;
  
  BSG_UINT32 size = __FMT_MASK_SIZE(type);
  BSG_UINT32 format = __FMT_MASK_FORMAT(type);
  
  if (format == __FMT_CONST) {// We are dealing with a fixed length value ie. UINT32

    BSG_UINT32 val = BSG_UnpackConst(s, size);

    if (dst) {
      switch (size) {
      case 1: *(BYTE *) d = (BSG_BYTE) val; break;
      case 2: *(unsigned short*) d = (unsigned short) val; break;
      case 4: *(BSG_UINT32*) d = (BSG_UINT32) val; break;
      }
    }

    s += size;
    d += size;
  } else if (format == __FMT_DATA) {// We are dealing with raw data. Not sure when this is used.
    if (dst)
      memcpy(d, s, size);

    d += size;
    s += size;
  } else if (format == __FMT_SIZE || format == __FMT_HSIZE) {// It's a size, followed by that much data or handles
    
    BSG_UINT32 psize = BSG_UnpackConst(s, size);
    
    if (psize > BSG_MAX_BUF_SIZE) {
      vtpmlogerror(VTPM_LOG_BSG, "BSG_Unpack runs into var-sized data bigger than %u bytes!!\n",
	       BSG_MAX_BUF_SIZE);
      return -1;
    }
    
    if (dst) {
      switch (size) {
      case 1: *(BYTE *) d = (BSG_BYTE) psize; break;
      case 2: *(unsigned short*) d = (unsigned short) psize; break;
      case 4: *(BSG_UINT32*) d = (BSG_UINT32) psize; break;
      }
    }

    s += size;
    d += size;
    
    BSG_BYTE* pdata = NULL;
    
    if (psize) {
      if (format == __FMT_HSIZE) { // This is a list of psize Handles
	if (dst) {
	  BSG_HANDLE* s2 = (BSG_HANDLE*) s;
	  pdata = (BSG_BYTE *)malloc(psize * sizeof(BSG_HANDLE));
          if (!pdata)
            return -1;
          
	  BSG_HANDLE* p2 = (BSG_HANDLE*) pdata;
	  BSG_UINT32 i;
	  for (i = 0; i < psize; i++) {
	    BSG_PackConst(s2[i], 4, (BSG_BYTE*)(p2 + i));
	  }
	}
	s += psize * sizeof(BSG_HANDLE);
      } else { // If it's not psize handles, it's psize data.
	if (dst) {
	  pdata = (BSG_BYTE *)malloc(sizeof(BSG_BYTE) * psize);
          if (!pdata)
            return -1;
	  memcpy(pdata, s, psize);
	}
	s += psize;
      }
    }
    if (dst)
      *(void**) d = pdata;

    d += sizeof(void*);
  } else if (format == __FMT_PACKED) {

    // this doesn't make sense for unpacking!
    vtpmlogerror(VTPM_LOG_BSG, "BSG_Unpack() called with format __FMT_PACKED. "
							   "This does not make sense\n");
    
    return -1;
  } else if (format == 0) {// No flags are set. This is a structure & it should
                          // be looked up in the bsg_s_fmt[]

    const BSG_Format* x = find_format (type);
    if (x == NULL) {
      vtpmlogerror(VTPM_LOG_BSG, "BSG_Unpack: cannot find type %d\n", type);
      return -1;
    }
    
    const BSG_UINT32* f = x->fields;
    for (; *f; f++) {
      int fsize = BSG_Unpack_private((BSG_Type) *f, s, dst ? &d:NULL);
      if (fsize <= 0)
	return fsize;
      s += fsize;
    }
  }

  if (dst)
    *dst = d;
  return (s - src);
}

/**
 * Free memory associated with unpacked TCPA structure
 * @type: TCPA structure type
 * @src: (IN) TCPA structure (OUT) end of TCPA structure
 * Note: Destroy should be called on all structures created with Unpack
 *       to ensure that any allocated memory is freed
 */
static void BSG_Destroy_private(BSG_Type type, BSG_BYTE** src) {
  BSG_BYTE* s = *src;
  
  BSG_UINT32 size = __FMT_MASK_SIZE(type);
  BSG_UINT32 format = __FMT_MASK_FORMAT(type);
  
  if ((src == NULL) || (*src == NULL)) {
        vtpmlogerror(VTPM_LOG_BSG, "BSG_Destroy() called with NULL src\n");
    return;
  }

  if (format == __FMT_CONST || format == __FMT_DATA)
    s += size;
  else if (format == __FMT_SIZE || format == __FMT_HSIZE) {
    s += size;
    BSG_BYTE* ptr = *(BSG_BYTE**) s;
    free(ptr);
    s += sizeof(void*);
  } else if (format == __FMT_PACKED) {

    // this doesn't make sense for unpacking, hence also for Destroy()
    vtpmlogerror(VTPM_LOG_BSG, "BSG_Destroy() called with format __FMT_PACKED. "
							   "This does not make sense\n");
    
    return;
  } else if (format == 0) {
    const BSG_Format* x = find_format (type);
    if (x == NULL) {
      vtpmlogerror(VTPM_LOG_BSG, "BSG_Destroy: cannot find type %d\n", type);
      return;
    }
    
    const BSG_UINT32* f = x->fields;
    for (; *f; f++)
      BSG_Destroy_private((BSG_Type) *f, &s);
  }

  *src = s;
}

int BSG_Pack(BSG_Type type, const void* src, BSG_BYTE* dst)
{
  const BSG_BYTE* src2 = (const BSG_BYTE*) src;
  return BSG_Pack_private(type, &src2, dst);
}

int BSG_Unpack(BSG_Type type, const BSG_BYTE* src, void* dst)
{
  BSG_BYTE* dst2 = (BSG_BYTE*) dst;
  return BSG_Unpack_private(type, src, dst ? &dst2:NULL);
}

void BSG_Destroy(BSG_Type type, void* src)
{
  BSG_BYTE* src2 = (BSG_BYTE*) src;
  BSG_Destroy_private(type, &src2);
}
    
/**
 * Pack a 8/16/32-bit constant into a buffer in big-endian format
 * @val: constant value
 * @size: constant size in bytes (1, 2, or 4)
 * @dst: (OUT) buffer
 */
void BSG_PackConst(BSG_UINT32 val, int size, BSG_BYTE* dst) {
  bsglog ("BSG: PackConst on %d of size %i into address %p\n", val, size, dst);
  
  switch (size) {
  case 4:
    dst[0] = (BSG_BYTE)((val >> 24) & 0xff);
    dst[1] = (BSG_BYTE)((val >> 16) & 0xff);
    dst[2] = (BSG_BYTE)((val >> 8) & 0xff);
    dst[3] = (BSG_BYTE)(val & 0xff);
    break;
  case 2:
    dst[0] = (BSG_BYTE)((val >> 8) & 0xff);
    dst[1] = (BSG_BYTE)(val & 0xff);
    break;
  case 1:
    dst[0] = (BSG_BYTE)(val & 0xff);
    break;
  }
}

/**
 * Unpack a 8/16/32-bit constant from a buffer in big-endian format
 * @src: buffer
 * @size: constant size in bytes (1, 2, or 4)
 */
BSG_UINT32 BSG_UnpackConst(const BSG_BYTE* src, int size) {
  BSG_UINT32 val = 0;
  
  if (src == NULL) 
    return 0;
  
  switch (size) {
  case 4:
    val = (((BSG_UINT32) src[0]) << 24
	   | ((BSG_UINT32) src[1]) << 16
	   | ((BSG_UINT32) src[2]) << 8
	   | (BSG_UINT32) src[3]);
    break;
  case 2:
    val = (((BSG_UINT32) src[0]) << 8 | (BSG_UINT32) src[1]);
    break;
  case 1:
    val = (BSG_UINT32) src[0];
    break;
  }  
  return val;
}

// Pack a list of parameters. Beware not to send values, but rather you must
// send a pointer to your values Instead. This includes UINT32's.
int BSG_PackList( BSG_BYTE* dst, int ParamCount, ... ) {
  int ParamNumber;
  BSG_Type format; 
  BSG_BYTE* val = NULL;
  int size=0;
  
  va_list paramList;
  va_start( paramList, ParamCount );

  for( ParamNumber = 1; ParamNumber <= ParamCount; ParamNumber++) {
    //Strangeness with int is because gcc wanted an int rather than a enum of ints.
    format =  (BSG_Type) va_arg( paramList, int );
    val = va_arg( paramList, BSG_BYTE* );    
    size += BSG_Pack(format, val, dst == NULL ? NULL : dst + size);
  }
  
  va_end (paramList);
  
  return size;
}

// Unpack a list of parameters. 
int BSG_UnpackList( const BSG_BYTE* src, int ParamCount, ... ) {
  int ParamNumber = 0;
  BSG_Type format; 
  BSG_BYTE* val = NULL;
  int size = 0;
  
  va_list paramList;
  va_start( paramList, ParamCount );
  
  for( ParamNumber = 1; ParamNumber <= ParamCount; ParamNumber++) {
    format = (BSG_Type) va_arg( paramList, int );
    val  = va_arg( paramList, BSG_BYTE* );
    
    size += BSG_Unpack(format, src + size, val);
  }
  
  va_end( paramList );   
  
  return size;
}

// Destroy any memory allocated by calls to unpack 
void BSG_DestroyList(int ParamCount, ... ) {
  int ParamNumber = 0;
  BSG_Type argType; 
  BSG_BYTE* paramValue = NULL;
  
  va_list paramList;
  va_start( paramList, ParamCount );
  
  for( ParamNumber = 1; ParamNumber <= ParamCount; ParamNumber++) {
    argType = (BSG_Type) va_arg( paramList, int );
    paramValue  = va_arg( paramList, BSG_BYTE* );
    
    BSG_Destroy(argType, paramValue);
  }
  
  va_end( paramList );   
  
  return;
}


// and a tuple version
TPM_RESULT BSG_DestroyTuple (int numParams, pack_tuple_t params[]) {
  int i;
  
  for (i = 0; i < numParams; i++)
    BSG_Destroy (params[i].type, params[i].addr);

  return TPM_SUCCESS;
}


//
// wrappers of Pack and PackList which malloc the ouput buffer. to be freed
// by the caller later
//

int BSG_PackMalloc (BSG_Type type, const void* src, BSG_BYTE** o_dst) {
  int size = BSG_Pack (type, src, NULL);
  BSG_BYTE * dest = (BSG_BYTE*) malloc (size);
  if (dest == NULL)
    return -1;

  size = BSG_Pack(type, src, dest);
  *o_dst = dest;
  return size;
}



int BSG_PackListMalloc(BSG_BYTE** outBuffer, int ParamCount, ... ) {
  va_list args;
  int size;
  
  va_start (args, ParamCount);
  size = BSG_PackList (NULL, ParamCount, args);
  va_end (args);
  
  BSG_BYTE * dest = (BSG_BYTE*) malloc (size);
  if (dest == NULL)
    return -1;

  va_start (args, ParamCount);
  size = BSG_PackList (dest, ParamCount, args);
  va_end (args);
  
  *outBuffer = dest;
  return size;
}
