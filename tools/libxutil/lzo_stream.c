/* $Id: lzo_stream.c,v 1.4 2003/09/30 15:22:53 mjw Exp $ */
#define __FILE_ID_INFO "$Id: lzo_stream.c,v 1.4 2003/09/30 15:22:53 mjw Exp $"
#include <what.h>
static char __rcsid[] __attribute__((unused)) = WHAT_ID __FILE_ID_INFO;
/*
 * Copyright (C) 2003 Hewlett-Packard Company.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/** @file
 * An IOStream implementation using LZO to provide compression and decompression.
 * This is designed to provide reasonable compression without output latency.
 * Flushing an LZO stream flushes all pending data to the underlying stream.
 * This is essential for stream-based (e.g. networked) applications.
 *
 * A compressed data stream is a sequence of blocks.
 * Each block except the last is the plain data size followed by the compressed data size
 * and the compressed data. The last block has plain data size zero and omits the rest.
 * Sizes are 4-byte unsigned in network order. If the compressed size is smaller than
 * the plain size the block data is compressed, otherwise it is plain (uncompressed).
 *
 * This format allows compressed data to be read from a stream without reading
 * past the logical end of compressed data.
 *
 * @author Mike Wray <mike.wray@hpl.hp.com>
 */
#ifndef __KERNEL__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "lzo1x.h"

#include "allocate.h"
#include "lzo_stream.h"
#include "file_stream.h"
#include "marshal.h"

#define dprintf(fmt, args...) fprintf(stdout, "[DEBUG] LZO>%s" fmt, __FUNCTION__, ##args)
#define wprintf(fmt, args...) fprintf(stderr, "[WARN]  LZO>%s" fmt, __FUNCTION__, ##args)
#define iprintf(fmt, args...) fprintf(stdout, "[INFO]  LZO>%s" fmt, __FUNCTION__, ##args)
#define eprintf(fmt, args...) fprintf(stderr, "[ERROR] LZO>%s" fmt, __FUNCTION__, ##args)

static int lzo_read(IOStream *s, void *buf, size_t size, size_t count);
static int lzo_write(IOStream *s, const void *buf, size_t size, size_t count);
static int lzo_print(IOStream *s, const char *msg, va_list args);
static int lzo_getc(IOStream *s);
static int lzo_error(IOStream *s);
static int lzo_close(IOStream *s);
static void lzo_free(IOStream *s);
static int lzo_flush(IOStream *s);

enum {
    LZO_WRITE = 1,
    LZO_READ = 2,
};

/** Methods used by a gzFile* IOStream. */
static const IOMethods lzo_methods = {
    read: lzo_read,
    write: lzo_write,
    print: lzo_print,
    getc:  lzo_getc,
    error: lzo_error,
    close: lzo_close,
    free:  lzo_free,
    flush: lzo_flush,
};

//#define PLAIN_SIZE (64 * 1024)
//#define PLAIN_SIZE (128 * 1024)
#define PLAIN_SIZE (512 * 1024)

//#define NOCOMPRESS

typedef struct LZOState {
    /** Flags. */
    int flags;
    /** Error indicator. */
    int error;
    /** Underlying stream for I/O. */
    IOStream *io;
    /** Working memory (only needed for compression, not decompression). */
    lzo_byte *memory;
    /** Buffer for plain (uncompressed) data. */
    lzo_byte *plain;
    /** Size of the plain buffer. */
    lzo_uint plain_size;
    /** Pointer into the plain buffer. */
    lzo_byte *plain_ptr;
    /** Number of bytes of plain data available. */
    lzo_uint plain_n;
    /** Buffer for compressed data. */
    lzo_byte *comp;
    /** Size of the compressed buffer. */
    lzo_uint comp_size;

    int plain_bytes;
    int comp_bytes;
} LZOState;

void LZOState_free(LZOState *z){
    if(!z) return;
    deallocate(z->memory);
    deallocate(z->plain);
    deallocate(z->comp);
    deallocate(z);
}

/** Maximum size of compressed data for the given plain data size.
 *
 * @param plain_size size of plain data
 * @return maximum size of compressed data
 */
static int comp_size(int plain_size){
    return plain_size + (plain_size / 64) + 16 + 3;
}

static int mode_flags(const char *mode, int *flags){
    int err = 0;
    int r=0, w=0;
    if(!mode){
        err = -EINVAL;
        goto exit;
    }
    for(; *mode; mode++){
        if(*mode == 'w') w = 1;
        if(*mode == 'r') r = 1;
    }
    if(r + w != 1){
        err = -EINVAL;
        goto exit;
    }
    if(r) *flags |= LZO_READ;
    if(w) *flags |= LZO_WRITE;
  exit:
    return err;
}

/** Get the stream state.
 * 
 * @param s lzo stream
 * @return stream state.
 */
static inline LZOState * lzo_state(IOStream *s){
    return s->data;
}

IOStream *lzo_stream_io(IOStream *s){
    LZOState *state = lzo_state(s);
    return state->io;
}

static inline void set_error(LZOState *state, int err){
    if(err < 0 && !state->error){
        state->error = err;
    }
}

int lzo_stream_plain_bytes(IOStream *s){
    LZOState *state = lzo_state(s);
    return state->plain_bytes;
}

int lzo_stream_comp_bytes(IOStream *s){
    LZOState *state = lzo_state(s);
    return state->comp_bytes;
}

float lzo_stream_ratio(IOStream *s){
    LZOState *state = lzo_state(s);
    float ratio = 0.0;
    if(state->comp_bytes){
        ratio = ((float) state->comp_bytes)/((float) state->plain_bytes);
    }
    return ratio;
}

static inline int LZOState_writeable(LZOState *state){
    return (state->flags & LZO_WRITE) != 0;
}

static inline int LZOState_readable(LZOState *state){
    return (state->flags & LZO_READ) != 0;
}

LZOState * LZOState_new(IOStream *io, int flags){
    int err = -ENOMEM;
    LZOState *z = ALLOCATE(LZOState);
    //dprintf(">\n");
    if(!z) goto exit;
    z->io = io;
    z->flags = flags;
    if(LZOState_writeable(z)){
        z->memory = allocate(LZO1X_1_MEM_COMPRESS);
        if(!z->memory) goto exit;
    }
    z->plain_size = PLAIN_SIZE;
    z->plain = allocate(z->plain_size);
    if(!z->plain) goto exit;
    z->plain_ptr = z->plain;
    z->comp_size = comp_size(z->plain_size);
    z->comp = allocate(z->comp_size);
    if(!z->comp) goto exit;
    err = 0;
  exit:
    if(err){
        LZOState_free(z);
        z = NULL;
    }
    //dprintf("< z=%p\n", z);
    return z;
}

static int lzo_compress(LZOState *state){
    int err = 0;
    int k, comp_n;
    //dprintf(">\n");
    //dprintf(">plain=%p plain_n=%d comp=%p memory=%p\n", state->plain, state->plain_n, state->comp, state->memory);
    // Compress the plain buffer.
    err = lzo1x_1_compress(state->plain, state->plain_n,
                           state->comp, &comp_n,
                           state->memory);
    //dprintf("> err=%d plain_n=%d comp_n=%d\n", err, state->plain_n, comp_n);
    // Write plain size, compressed size.
    err = marshal_uint32(state->io, state->plain_n);
    if(err) goto exit;
    err = marshal_uint32(state->io, comp_n);
    if(err) goto exit;
    //dprintf("> write data...\n");
    // Write the smaller of the compressed and plain data.
    if(state->plain_n < comp_n){
        k = state->plain_n;
        err = marshal_bytes(state->io, state->plain, state->plain_n);
    } else {
        k = comp_n;
        err = marshal_bytes(state->io, state->comp, comp_n);
    }
    if(err) goto exit;
    // Total output bytes.
    k+= 8;
    //dprintf("> wrote %d bytes\n", k);
    state->plain_bytes += state->plain_n;
    state->comp_bytes += k;
    //dprintf("> plain=%d, comp=%d, ratio=%3.2f\n",
    //        state->plain_bytes, state->comp_bytes,
    //        ((float)state->comp_bytes)/((float)state->plain_bytes));
    // Reset the plain buffer.
    state->plain_ptr = state->plain;
    state->plain_n = 0;
    err = k;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

static int lzo_decompress(LZOState *state){
    int plain_n, comp_n;
    int err, k;
    //dprintf(">\n");
    err = unmarshal_uint32(state->io, &plain_n);
    //dprintf("> err=%d plain_n=%d\n", err, plain_n);
    if(err) goto exit;
    state->comp_bytes += 4;
    if(plain_n == 0) goto exit;
    err = unmarshal_uint32(state->io, &comp_n);
    //dprintf("> err=%d comp_n=%d\n", err, comp_n);
    if(err) goto exit;
    state->comp_bytes += 4;
    if(plain_n > state->plain_size){
        err = -EINVAL;
        goto exit;
    }
    if(comp_n > plain_n){
        //dprintf("> reading plain data %d...\n", plain_n);
        k = plain_n;
        err = unmarshal_bytes(state->io, state->plain, plain_n);
        state->plain_n = plain_n;
    } else {
        //dprintf("> reading comp data %d...\n", comp_n);
        k = comp_n;
        err = unmarshal_bytes(state->io, state->comp, comp_n);
        //dprintf("> decompress comp_n=%d\n", comp_n);
        err = lzo1x_decompress(state->comp, comp_n,
                               state->plain, &state->plain_n,
                               state->memory);
        //dprintf("> err=%d plain=%d state->plain_n=%d\n", err, plain_n, state->plain_n);
        if(err != LZO_E_OK || state->plain_n != plain_n){
            // Bad. Corrupted input.
            err = -EINVAL;
            eprintf("> Corrupted!\n");
            goto exit;
        }
    }
    state->comp_bytes += k;
    state->plain_bytes += state->plain_n;
    state->plain_ptr = state->plain;
    err = k;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

/** Write to the underlying stream using fwrite();
 *
 * @param stream destination
 * @param buf data
 * @param size size of data elements
 * @param count number of data elements to write
 * @return number of data elements written
 */
static int lzo_write(IOStream *s, const void *buf, size_t size, size_t count){
    int err = 0;
    int n = size * count; // Total number of bytes to write.
    int chunk;            // Size of chunk to write.
    int remaining;        // Number of bytes remaining to write.
    int space;            // Amount of space left in plain buffer.
    LZOState *state = lzo_state(s);
#ifdef NOCOMPRESS
    //dprintf("> buf=%p size=%d count=%d\n", buf, size, count);
    err = IOStream_write(state->io, buf, size, count);
    //dprintf("< err=%d\n", err);
#else
    //dprintf("> buf=%p size=%d count=%d n=%d\n", buf, size, count, n);
    remaining = n;
    space = state->plain_size - state->plain_n;
    //dprintf("> plain=%p plain_ptr=%p plain_n=%d space=%d\n",
    //        state->plain, state->plain_ptr, state->plain_n, space);
    while(remaining){
        chunk = remaining;
        if(chunk > space) chunk = space;
        //dprintf("> memcpy %p %p %d\n", state->plain_ptr, buf, chunk);
        memcpy(state->plain_ptr, buf, chunk);
        remaining -= chunk;
        space -= chunk;
        state->plain_ptr += chunk;
        state->plain_n += chunk;
        if(space == 0){
            // Input buffer is full. Compress and write it.
            err = lzo_compress(state);
            if(err < 0) goto exit;
            space = state->plain_size - state->plain_n;
        }
    }
    err = (size > 1 ? n / size : n);
  exit:
    set_error(state, err);
#endif
    return err;
}


/** Read from the underlying stream.
 *
 * @param stream input
 * @param buf where to put input
 * @param size size of data elements
 * @param count number of data elements to read
 * @return number of data elements read
 */
static int lzo_read(IOStream *s, void *buf, size_t size, size_t count){
    int err = 0;
    int k = 0;                     // Number of (plain) bytes read.
    int remaining = size * count;  // Number of bytes remaining to read.
    int chunk;                     // Size of chunk to read.
    LZOState *state = lzo_state(s);
#ifdef NOCOMPRESS
    //dprintf("> buf=%p size=%d count=%d\n", buf, size, count);
    err = IOStream_read(state->io, buf, size, count);
    //dprintf("< err=%d\n", err);
#else
    if(!(state->flags & LZO_READ)){
        err = -EINVAL;
        goto exit;
    }
    while(remaining){
        if(state->plain_n == 0){
            // No more plain input, decompress some more.
            err = lzo_decompress(state);
            if(err < 0) goto exit;
            // Stop reading if there is no more input.
            if(err == 0 || state->plain_n == 0) break;
        }
        chunk = remaining;
        if(chunk > state->plain_n) chunk = state->plain_n;
        memcpy(buf, state->plain_ptr, chunk);
        k += chunk;
        buf += chunk;
        state->plain_ptr += chunk;
        state->plain_n -= chunk;
        remaining -= chunk;
    }
    err = k;
  exit:
    set_error(state, err);
#endif
    return err;
}

/** Print to the underlying stream.
 * Returns 0 if the formatted output is too big for the internal buffer.
 *
 * @param s lzo stream
 * @param msg format to use
 * @param args arguments
 * @return result of the print
 */
static int lzo_print(IOStream *s, const char *msg, va_list args){
    char buf[1024];
    int buf_n = sizeof(buf);
    int n;
    LZOState *state = lzo_state(s);
    if(!LZOState_writeable(state)){
        n = -EINVAL;
        goto exit;
    }
    n = vsnprintf(buf, buf_n, (char*)msg, args);
    if(n < 0) goto exit;
    if(n > buf_n){
        n = 0;
    } else {
        n = lzo_write(s, buf, 1, n);
    }
  exit:
    return n;
}

/** Read a character from the underlying stream
 *
 * @param s lzo stream
 * @return character read, IOSTREAM_EOF on end of file (or error)
 */
static int lzo_getc(IOStream *s){
    int err;
    char c;
    err = lzo_read(s, &c, 1, 1);
    if(err < 1) c = EOF;
    err = (c==EOF ? IOSTREAM_EOF : c);
    return err;
}

/** Flush any pending input to the underlying stream.
 *
 * @param s lzo stream
 * @return 0 on success, error code otherwise
 */
static int lzo_flush(IOStream *s){
    int err = 0;
    LZOState *state = lzo_state(s);
    //dprintf(">\n");
#ifdef NOCOMPRESS
    err = IOStream_flush(state->io);
#else    
    if(!LZOState_writeable(state)){
        err = -EINVAL;
        goto exit;
    }
    if(state->plain_n){
        err = lzo_compress(state);
        if(err < 0) goto exit;
    }
    err = IOStream_flush(state->io);
  exit:
    set_error(state, err);
#endif
    //dprintf("< err=%d\n", err);
    return (err < 0 ? err : 0);
}

/** Check if a stream has an error.
 *
 * @param s lzo stream
 * @return code if has an error, 0 otherwise
 */
static int lzo_error(IOStream *s){
    int err = 0;
    LZOState *state = lzo_state(s);
    err = state->error;
    if(err) goto exit;
    err = IOStream_error(state->io);
  exit:
    return err;
}

int lzo_stream_finish(IOStream *s){
    int err = 0;
    LZOState *state = lzo_state(s);
    if(!LZOState_writeable(state)){
        err = -EINVAL;
        goto exit;
    }
    err = lzo_flush(s);
    if(err < 0) goto exit;
    err = marshal_int32(state->io, 0);
  exit:
    return err;
}        

/** Close an lzo stream.
 *
 * @param s lzo stream to close
 * @return result of the close
 */
static int lzo_close(IOStream *s){
    int err = 0;
    LZOState *state = lzo_state(s);
#ifdef NOCOMPRESS
    err = IOStream_close(state->io);
#else    
    if(LZOState_writeable(state)){
        err = lzo_stream_finish(s);
    }        
    err = IOStream_close(state->io);
    set_error(state, err);
#endif
    return err;
}

/** Free an lzo stream.
 *
 * @param s lzo stream
 */
static void lzo_free(IOStream *s){
    LZOState *state = lzo_state(s);
    IOStream_free(state->io);
    LZOState_free(state);
    s->data = NULL;
}

/** Create an lzo stream for an IOStream.
 *
 * @param io stream to wrap
 * @return new IOStream using f for i/o
 */
IOStream *lzo_stream_new(IOStream *io, const char *mode){
    int err = -ENOMEM;
    int flags = 0;
    IOStream *zio = NULL;
    LZOState *state = NULL;

    zio = ALLOCATE(IOStream);
    if(!zio) goto exit;
    err = mode_flags(mode, &flags);
    if(err) goto exit;
    state = LZOState_new(io, flags);
    if(!state) goto exit;
    err = 0;
    zio->data = state;
    zio->methods = &lzo_methods;
  exit:
    if(err){
        if(state) LZOState_free(state);
        if(zio) deallocate(zio);
        zio = NULL;
    }
    return zio;
}

/** IOStream version of fdopen().
 *
 * @param fd file descriptor
 * @param flags giving the mode to open in (as for fdopen())
 * @return new stream for the open file, or NULL if failed
 */
IOStream *lzo_stream_fdopen(int fd, const char *mode){
    int err = -ENOMEM;
    IOStream *io = NULL, *zio = NULL;
    io = file_stream_fdopen(fd, mode);
    if(!io) goto exit;
    zio = lzo_stream_new(io, mode);
    if(!io) goto exit;
    err = 0;
  exit:
    if(err){
        IOStream_free(io);
        IOStream_free(zio);
        zio = NULL;
    }
    return zio;
}
#endif
