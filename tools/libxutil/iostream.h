#ifndef _XC_LINUX_SAVE_H_
#define _XC_LINUX_SAVE_H_

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

#include "allocate.h"

/** End of input return value. */
#define IOSTREAM_EOF -1

/** An input/output abstraction.
 */
typedef struct IOStream IOStream;

/** Record of the functions to use for operations on an
 * IOStream implementation.
 */
typedef struct IOMethods {
    /** Read function.  Called with the user data, buffer to read into
     * and number of bytes to read.  Must return number of bytes read
     * on success, less than zero on error.
     */
    int (*read)(IOStream *stream, void *buf, size_t n);

    /** Write function. Called with user data, buffer to write and
     * number of bytes to write. Must return number of bytes written on
     * success, less than zero otherwise.
     */
    int (*write)(IOStream *stream, const void *buf, size_t n);

    int (*flush)(IOStream *s);

    int (*error)(IOStream *s);

    int (*close)(IOStream *s);

    void (*free)(IOStream *s);

    void (*lock)(IOStream *s);
    void (*unlock)(IOStream *s);

} IOMethods;

/** Abstract i/o object.
 */
struct IOStream {
    /** Methods to use to implement operations. */
    const IOMethods *methods;
    /** Private state for the implementation. */
    const void *data;
    /** Flag indicating whether the stream is closed. */
    int closed;
    /** Number of bytes written. */
    int written;
    /** Number of bytes read. */
    int read;
};


/** IOStream version of stdin. */
extern IOStream *iostdin;

/** IOStream version of stdout, */
extern IOStream *iostdout;

/** IOStream version of stderr. */
extern IOStream *iostderr;

extern int IOStream_print(IOStream *io, const char *format, ...);
extern int IOStream_vprint(IOStream *io, const char *format, va_list args);

/** Read from a stream.
 *
 * @param stream input
 * @param buf where to put input
 * @param n number of bytes to read
 * @return if ok, number of bytes read, otherwise negative error code
 */
static inline int IOStream_read(IOStream *stream, void *buf, size_t n){
    int result = 0;
    if(stream->closed) goto exit;
    if(!stream->methods || !stream->methods->read){
        result = -EINVAL;
        goto exit;
    }
    result = stream->methods->read(stream, buf, n);
    if(result > 0){
        stream->read += result;
    }
  exit:
    return result;
}

/** Write to a stream.
 *
 * @param stream input
 * @param buf where to put input
 * @param n number of bytes to write
 * @return if ok, number of bytes read, otherwise negative error code
 */
static inline int IOStream_write(IOStream *stream, const void *buf, size_t n){
    int result = 0;
    if(stream->closed) goto exit;
    if(!stream->methods || !stream->methods->write){
        result = -EINVAL;
        goto exit;
    }
    result = stream->methods->write(stream, buf, n);
    if(result > 0){
        stream->written += result;
    }
  exit:
    return result;
}

/** Flush the stream.
 *
 * @param stream stream
 * @return 0 on success, IOSTREAM_EOF otherwise
 */
static inline int IOStream_flush(IOStream *stream){
    int result = 0;
    if(stream->closed){
        result = IOSTREAM_EOF;
    } else if(stream->methods->flush){
        result = stream->methods->flush(stream);
        if(result < 0) result = IOSTREAM_EOF;
    }
    return result;
}

/** Check whether the stream has an error.
 *
 * @param stream to check
 * @return 1 for error, 0 otherwise
 */
static inline int IOStream_error(IOStream *stream){
    int err = 0;
    if(stream->methods && stream->methods->error){
       err = stream->methods->error(stream);
    }
    return err;
}

/** Close the stream.
 *
 * @param stream to close
 * @return 1 for error, 0 otherwise
 */
static inline int IOStream_close(IOStream *stream){
    int err = 1;
    if(stream->methods && stream->methods->close){
        err = stream->methods->close(stream);
    }
    return err;
}

/** Test if the stream has been closed.
 *
 * @param stream to check
 * @return 1 if closed, 0 otherwise
 */
static inline int IOStream_is_closed(IOStream *stream){
  return stream->closed;
}

/** Free the memory used by the stream.
 *
 * @param stream to free
 */
static inline void IOStream_free(IOStream *stream){
  if(stream->methods && stream->methods->free){
    stream->methods->free(stream);
  }
  *stream = (IOStream){};
  deallocate(stream);
}


/** Print a character to a stream, like fputc().
 *
 * @param stream to print to
 * @param c character to print
 * @return result code from the print
 */
static inline int IOStream_putc(IOStream *stream, int c){
    int err;
    unsigned char b = (unsigned char)c;
    err = IOStream_write(stream, &b, 1);
    if(err < 1){
        err = IOSTREAM_EOF;
    } else {
        err = b;
    }
    return err;
}

/** Read from a stream, like fgetc().
 *
 * @param stream to read from
 * @return IOSTREAM_EOF on error, character read otherwise
 */
static inline int IOStream_getc(IOStream *stream){
    int err, rc;
    unsigned char b;

    err = IOStream_read(stream, &b, 1);
    if(err < 1){
        rc = IOSTREAM_EOF;
    } else {
        rc = b;
    }
    return rc;
}

/** Get number of bytes read.
 *
 * @param stream to get from
 * @return number of bytes read
 */
static inline int IOStream_get_read(IOStream *stream){
    return stream->read;
}

/** Get number of bytes written.
 *
 * @param stream to get from
 * @return number of bytes written
 */
static inline int IOStream_get_written(IOStream *stream){
    return stream->written;
}


#endif /* ! _XC_LINUX_SAVE_H_ */
