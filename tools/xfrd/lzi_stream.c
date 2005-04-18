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
 * An IOStream implementation using LZI to provide compression and decompression.
 * This is designed to provide compression without output latency.
 * Flushing an LZI stream flushes all pending data to the underlying stream.
 * This is essential for stream-based (e.g. networked) applications.
 *
 * A compressed data stream is a sequence of blocks.
 * Each block is the block size followed by the compressed data.
 * The last block has size zero.
 * Sizes are 4-byte unsigned in network order.
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

#include "zlib.h"

#include "allocate.h"
#include "lzi_stream.h"
#include "file_stream.h"
#include "marshal.h"

#define dprintf(fmt, args...) fprintf(stdout, "[DEBUG] LZI>%s" fmt, __FUNCTION__, ##args)
#define wprintf(fmt, args...) fprintf(stderr, "[WARN]  LZI>%s" fmt, __FUNCTION__, ##args)
#define iprintf(fmt, args...) fprintf(stdout, "[INFO]  LZI>%s" fmt, __FUNCTION__, ##args)
#define eprintf(fmt, args...) fprintf(stderr, "[ERROR] LZI>%s" fmt, __FUNCTION__, ##args)

static int lzi_read(IOStream *s, void *buf, size_t n);
static int lzi_write(IOStream *s, const void *buf, size_t n);
static int lzi_error(IOStream *s);
static int lzi_close(IOStream *s);
static void lzi_free(IOStream *s);
static int lzi_flush(IOStream *s);

enum {
    LZI_WRITE = 1,
    LZI_READ = 2,
};

/** Methods used by a gzFile* IOStream. */
static const IOMethods lzi_methods = {
    read:  lzi_read,
    write: lzi_write,
    error: lzi_error,
    close: lzi_close,
    free:  lzi_free,
    flush: lzi_flush,
};

#define BUFFER_SIZE (512 * 1024)

typedef struct LZIState {
    z_stream zstream;
    void *inbuf;
    uint32_t inbuf_size;
    void *outbuf;
    uint32_t outbuf_size;
    /** Underlying stream for I/O. */
    IOStream *io;
    /** Flags. */
    int flags;
    /** Error indicator. */
    int error;
    int eof;
    int plain_bytes;
    int comp_bytes;
    int zstream_initialized;
    int flushed;
} LZIState;

static inline int LZIState_writeable(LZIState *s){
    return (s->flags & LZI_WRITE) != 0;
}

static inline int LZIState_readable(LZIState *s){
    return (s->flags & LZI_READ) != 0;
}

void LZIState_free(LZIState *z){
    if(!z) return;
    if(z->zstream_initialized){
        if(LZIState_writeable(z)){
            deflateEnd(&z->zstream);
        } else if(LZIState_readable(z)){
            inflateEnd(&z->zstream);
        }
    }
    deallocate(z->inbuf);
    deallocate(z->outbuf);
    deallocate(z);
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
    if(r) *flags |= LZI_READ;
    if(w) *flags |= LZI_WRITE;
  exit:
    return err;
}

/** Get the stream state.
 * 
 * @param s lzi stream
 * @return stream state.
 */
static inline LZIState * lzi_state(IOStream *io){
    return (LZIState*)io->data;
}

IOStream *lzi_stream_io(IOStream *io){
    LZIState *s = lzi_state(io);
    return s->io;
}

static inline void set_error(LZIState *s, int err){
    if(err < 0 && !s->error){
        s->error = err;
    }
}

static int zerror(LZIState *s, int err){
    if(err){
        //dprintf("> err=%d\n", err);
        if(err < 0) set_error(s, -EIO);
    }
    return s->error;
}

int lzi_stream_plain_bytes(IOStream *io){
    LZIState *s = lzi_state(io);
    return s->plain_bytes;
}

int lzi_stream_comp_bytes(IOStream *io){
    LZIState *s = lzi_state(io);
    return s->comp_bytes;
}

float lzi_stream_ratio(IOStream *io){
    LZIState *s = lzi_state(io);
    float ratio = 0.0;
    if(s->comp_bytes){
        ratio = ((float) s->comp_bytes)/((float) s->plain_bytes);
    }
    return ratio;
}

static int alloc(void **p, int n){
    *p = allocate(n);
    return (p ? 0 : -ENOMEM);
}

LZIState * LZIState_new(IOStream *io, int flags){
    int err = -ENOMEM;
    int zlevel = Z_BEST_SPEED; // Level 1 compression - fastest.
    int zstrategy = Z_DEFAULT_STRATEGY;
    int zwindow = MAX_WBITS;
    int zmemory = 8;
    LZIState *z = ALLOCATE(LZIState);

    //dprintf(">\n");
    if(!z) goto exit;
    z->io = io;
    z->flags = flags;

    if(LZIState_writeable(z)){
        z->outbuf_size = BUFFER_SIZE;
        /* windowBits is passed < 0 to suppress zlib header */
        err = deflateInit2(&z->zstream, zlevel, Z_DEFLATED, -zwindow, zmemory, zstrategy);
        if (err != Z_OK) goto exit;
        z->zstream_initialized = 1;
        err = alloc(&z->outbuf, z->outbuf_size);
        if(err) goto exit;
        z->zstream.next_out = z->outbuf;
        z->zstream.avail_out = z->outbuf_size;
    } else {
        z->inbuf_size = BUFFER_SIZE;
        err = alloc(&z->inbuf, z->inbuf_size);
        if(err) goto exit;
        ///z->zstream.next_in  = z->inbuf;

        /* windowBits is passed < 0 to tell that there is no zlib header.
         * Note that in this case inflate *requires* an extra "dummy" byte
         * after the compressed stream in order to complete decompression and
         * return Z_STREAM_END. Here the gzip CRC32 ensures that 4 bytes are
         * present after the compressed stream.
         */
        err = inflateInit2(&z->zstream, -zwindow);
        if(err != Z_OK) goto exit;
        z->zstream_initialized = 1;
    }
        
  exit:
    if(err){
        LZIState_free(z);
        z = NULL;
    }
    //dprintf("< z=%p\n", z);
    return z;
}

int read_block(LZIState *s){
    int err = 0;
    uint32_t k = 0;
    //dprintf(">\n");
    if(s->eof) goto exit;
    err = unmarshal_uint32(s->io, &k);
    if(err) goto exit;
    if(k > s->inbuf_size){
        err = -EINVAL;
        goto exit;
    }
    if(k){
        err = unmarshal_bytes(s->io, s->inbuf, k);
        if(err) goto exit;
    } else {
        s->eof = 1;
    }        
    s->zstream.avail_in = k;
    s->zstream.next_in = s->inbuf;
    s->comp_bytes += 4;
    s->comp_bytes += k;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

int write_block(LZIState *s){
    int err = 0;
    int k = ((char*)s->zstream.next_out) - ((char*)s->outbuf);
    //int k2 = s->outbuf_size - s->zstream.avail_out;
    //dprintf("> k=%d k2=%d\n", k, k2);
    if(!k) goto exit;
    err = marshal_uint32(s->io, k);
    if(err) goto exit;
    err = marshal_bytes(s->io, s->outbuf, k);
    if(err) goto exit;
    s->zstream.next_out = s->outbuf;
    s->zstream.avail_out = s->outbuf_size;
    s->comp_bytes += 4;
    s->comp_bytes += k;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

int write_terminator(LZIState *s){
    int err = 0;
    char c = 0;
    err = marshal_uint32(s->io, 1);
    if(err) goto exit;
    err = marshal_bytes(s->io, &c, 1);
    if(err) goto exit;
    err = marshal_uint32(s->io, 0);
    if(err) goto exit;
    s->comp_bytes += 9;
  exit:
    return err;
}

/** Write to the underlying stream using fwrite();
 *
 * @param io destination
 * @param buf data
 * @param n number of bytes to write
 * @return number of bytes written
 */
static int lzi_write(IOStream *io, const void *buf, size_t n){
    int err = 0;
    LZIState *s = lzi_state(io);

    //dprintf("> buf=%p n=%d\n", buf, n);
    if(!LZIState_writeable(s)){
        err = -EINVAL;
        goto exit;
    }
    s->flushed = 0;
    s->zstream.next_in = (void*)buf;
    s->zstream.avail_in = n;
    while(s->zstream.avail_in){
        if(s->zstream.avail_out == 0){
            err = write_block(s);
            if(err) goto exit;
        }
        //dprintf("> 1 deflate avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
        //dprintf("> 1 deflate next_in=%p next_out=%p\n", s->zstream.next_in, s->zstream.next_out);
        err = zerror(s, deflate(&s->zstream, Z_NO_FLUSH));
        //dprintf("> 2 deflate avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
        //dprintf("> 2 deflate next_in=%p next_out=%p\n", s->zstream.next_in, s->zstream.next_out);
        if(err) goto exit;
    }
    err = n;
    s->plain_bytes += n;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}


/** Read from the underlying stream.
 *
 * @param io input
 * @param buf where to put input
 * @param n number of bytes to read
 * @return number of bytes read
 */
static int lzi_read(IOStream *io, void *buf, size_t n){
    int err, zerr;
    LZIState *s = lzi_state(io);

    //dprintf("> n=%d\n", n);
    if(!LZIState_readable(s)){
        err = -EINVAL;
        goto exit;
    }
    s->zstream.next_out = buf;
    s->zstream.avail_out = n;
    while(s->zstream.avail_out){
        if(s->zstream.avail_in == 0){
            err = read_block(s);
        }
        //dprintf("> 1 deflate avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
        zerr = inflate(&s->zstream, Z_NO_FLUSH);
        //dprintf("> 2 deflate avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
        if(zerr == Z_STREAM_END) break;
        //dprintf("> zerr=%d\n", zerr);
        err = zerror(s, zerr);
        if(err) goto exit;
    }
    err = n - s->zstream.avail_out;
    s->plain_bytes += err;
  exit:
    set_error(s, err);
    //dprintf("< err=%d\n", err);
    return err;
}

static int flush_output(LZIState *s, int mode){
    int err = 0, zerr;
    int done = 0;
    int avail_out_old;

    //dprintf("> avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
    if(s->flushed == 1 + mode) goto exit;
    //s->zstream.avail_in = 0; /* should be zero already anyway */
    for(;;){
        // Write any available output.
        if(done || s->zstream.avail_out == 0){
            err = write_block(s);
            if(err) goto exit;
            if(done) break;
        }
        //dprintf("> 1 deflate avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
        avail_out_old = s->zstream.avail_out;
        zerr = deflate(&s->zstream, mode);
        err = zerror(s, zerr);
        //dprintf("> 2 deflate avail_in=%d avail_out=%d\n", s->zstream.avail_in, s->zstream.avail_out);
        //dprintf("> deflate=%d\n", err);
        //done = (s->zstream.avail_out != 0);
        //done = (s->zstream.avail_in == 0) && (s->zstream.avail_out == avail_out_old);
        if(0 && mode == Z_FINISH){
            done = (zerr ==  Z_STREAM_END);
        } else {
            done = (s->zstream.avail_in == 0)
                //&& (s->zstream.avail_out == avail_out_old)
                && (s->zstream.avail_out != 0);
        }
    }
    s->flushed = 1 + mode;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

/** Flush any pending input to the underlying stream.
 *
 * @param s lzi stream
 * @return 0 on success, error code otherwise
 */
static int lzi_flush(IOStream *io){
    int err = 0;
    LZIState *s = lzi_state(io);
    //dprintf(">\n");
    if(!LZIState_writeable(s)){
        err = -EINVAL;
        goto exit;
    }
    err = flush_output(s, Z_SYNC_FLUSH);
    if(err) goto exit;
    err = IOStream_flush(s->io);
  exit:
    set_error(s, err);
    //dprintf("< err=%d\n", err);
    return (err < 0 ? err : 0);
}

/** Check if a stream has an error.
 *
 * @param s lzi stream
 * @return code if has an error, 0 otherwise
 */
static int lzi_error(IOStream *s){
    int err = 0;
    LZIState *state = lzi_state(s);
    err = state->error;
    if(err) goto exit;
    err = IOStream_error(state->io);
  exit:
    return err;
}

/** Close an lzi stream.
 *
 * @param s lzi stream to close
 * @return result of the close
 */
static int lzi_close(IOStream *io){
    int err = 0;
    LZIState *s = lzi_state(io);
    if(LZIState_writeable(s)){
        err = flush_output(s, Z_FINISH);
        if(err) goto exit;
        err = write_terminator(s);
        if(err) goto exit;
        err = IOStream_flush(s->io);
    }   
  exit:
    err = IOStream_close(s->io);
    set_error(s, err);
    return err;
}

/** Free an lzi stream.
 *
 * @param s lzi stream
 */
static void lzi_free(IOStream *s){
    LZIState *state = lzi_state(s);
    IOStream_free(state->io);
    LZIState_free(state);
    s->data = NULL;
}

/** Create an lzi stream for an IOStream.
 *
 * @param io stream to wrap
 * @return new IOStream using f for i/o
 */
IOStream *lzi_stream_new(IOStream *io, const char *mode){
    int err = -ENOMEM;
    int flags = 0;
    IOStream *zio = NULL;
    LZIState *state = NULL;

    zio = ALLOCATE(IOStream);
    if(!zio) goto exit;
    err = mode_flags(mode, &flags);
    if(err) goto exit;
    state = LZIState_new(io, flags);
    if(!state) goto exit;
    err = 0;
    zio->data = state;
    zio->methods = &lzi_methods;
  exit:
    if(err){
        if(state) LZIState_free(state);
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
IOStream *lzi_stream_fdopen(int fd, const char *mode){
    int err = -ENOMEM;
    IOStream *io = NULL, *zio = NULL;
    io = file_stream_fdopen(fd, mode);
    if(!io) goto exit;
    zio = lzi_stream_new(io, mode);
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
