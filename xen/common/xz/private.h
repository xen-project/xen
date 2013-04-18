/*
 * Private includes and definitions
 *
 * Author: Lasse Collin <lasse.collin@tukaani.org>
 *
 * This file has been put into the public domain.
 * You can do whatever you want with this file.
 */

#ifndef XZ_PRIVATE_H
#define XZ_PRIVATE_H

#ifdef __XEN__
#include <xen/kernel.h>
#include <asm/byteorder.h>
#endif

#define get_le32(p) le32_to_cpup((const uint32_t *)(p))

#if 1 /* ndef CONFIG_??? */
static inline u32 INIT get_unaligned_le32(void *p)
{
	return le32_to_cpup(p);
}

static inline void INIT put_unaligned_le32(u32 val, void *p)
{
	*(__force __le32*)p = cpu_to_le32(val);
}
#else
#include <asm/unaligned.h>

static inline u32 INIT get_unaligned_le32(void *p)
{
	return le32_to_cpu(__get_unaligned(p, 4));
}

static inline void INIT put_unaligned_le32(u32 val, void *p)
{
	__put_unaligned(cpu_to_le32(val), p, 4);
}
#endif

#define false 0
#define true 1

/**
 * enum xz_mode - Operation mode
 *
 * @XZ_SINGLE:              Single-call mode. This uses less RAM than
 *                          than multi-call modes, because the LZMA2
 *                          dictionary doesn't need to be allocated as
 *                          part of the decoder state. All required data
 *                          structures are allocated at initialization,
 *                          so xz_dec_run() cannot return XZ_MEM_ERROR.
 * @XZ_PREALLOC:            Multi-call mode with preallocated LZMA2
 *                          dictionary buffer. All data structures are
 *                          allocated at initialization, so xz_dec_run()
 *                          cannot return XZ_MEM_ERROR.
 * @XZ_DYNALLOC:            Multi-call mode. The LZMA2 dictionary is
 *                          allocated once the required size has been
 *                          parsed from the stream headers. If the
 *                          allocation fails, xz_dec_run() will return
 *                          XZ_MEM_ERROR.
 *
 * It is possible to enable support only for a subset of the above
 * modes at compile time by defining XZ_DEC_SINGLE, XZ_DEC_PREALLOC,
 * or XZ_DEC_DYNALLOC. The xz_dec kernel module is always compiled
 * with support for all operation modes, but the preboot code may
 * be built with fewer features to minimize code size.
 */
enum xz_mode {
	XZ_SINGLE,
	XZ_PREALLOC,
	XZ_DYNALLOC
};

/**
 * enum xz_ret - Return codes
 * @XZ_OK:                  Everything is OK so far. More input or more
 *                          output space is required to continue. This
 *                          return code is possible only in multi-call mode
 *                          (XZ_PREALLOC or XZ_DYNALLOC).
 * @XZ_STREAM_END:          Operation finished successfully.
 * @XZ_UNSUPPORTED_CHECK:   Integrity check type is not supported. Decoding
 *                          is still possible in multi-call mode by simply
 *                          calling xz_dec_run() again.
 *                          Note that this return value is used only if
 *                          XZ_DEC_ANY_CHECK was defined at build time,
 *                          which is not used in the kernel. Unsupported
 *                          check types return XZ_OPTIONS_ERROR if
 *                          XZ_DEC_ANY_CHECK was not defined at build time.
 * @XZ_MEM_ERROR:           Allocating memory failed. This return code is
 *                          possible only if the decoder was initialized
 *                          with XZ_DYNALLOC. The amount of memory that was
 *                          tried to be allocated was no more than the
 *                          dict_max argument given to xz_dec_init().
 * @XZ_MEMLIMIT_ERROR:      A bigger LZMA2 dictionary would be needed than
 *                          allowed by the dict_max argument given to
 *                          xz_dec_init(). This return value is possible
 *                          only in multi-call mode (XZ_PREALLOC or
 *                          XZ_DYNALLOC); the single-call mode (XZ_SINGLE)
 *                          ignores the dict_max argument.
 * @XZ_FORMAT_ERROR:        File format was not recognized (wrong magic
 *                          bytes).
 * @XZ_OPTIONS_ERROR:       This implementation doesn't support the requested
 *                          compression options. In the decoder this means
 *                          that the header CRC32 matches, but the header
 *                          itself specifies something that we don't support.
 * @XZ_DATA_ERROR:          Compressed data is corrupt.
 * @XZ_BUF_ERROR:           Cannot make any progress. Details are slightly
 *                          different between multi-call and single-call
 *                          mode; more information below.
 *
 * In multi-call mode, XZ_BUF_ERROR is returned when two consecutive calls
 * to XZ code cannot consume any input and cannot produce any new output.
 * This happens when there is no new input available, or the output buffer
 * is full while at least one output byte is still pending. Assuming your
 * code is not buggy, you can get this error only when decoding a compressed
 * stream that is truncated or otherwise corrupt.
 *
 * In single-call mode, XZ_BUF_ERROR is returned only when the output buffer
 * is too small or the compressed input is corrupt in a way that makes the
 * decoder produce more output than the caller expected. When it is
 * (relatively) clear that the compressed input is truncated, XZ_DATA_ERROR
 * is used instead of XZ_BUF_ERROR.
 */
enum xz_ret {
	XZ_OK,
	XZ_STREAM_END,
	XZ_UNSUPPORTED_CHECK,
	XZ_MEM_ERROR,
	XZ_MEMLIMIT_ERROR,
	XZ_FORMAT_ERROR,
	XZ_OPTIONS_ERROR,
	XZ_DATA_ERROR,
	XZ_BUF_ERROR
};

/**
 * struct xz_buf - Passing input and output buffers to XZ code
 * @in:         Beginning of the input buffer. This may be NULL if and only
 *              if in_pos is equal to in_size.
 * @in_pos:     Current position in the input buffer. This must not exceed
 *              in_size.
 * @in_size:    Size of the input buffer
 * @out:        Beginning of the output buffer. This may be NULL if and only
 *              if out_pos is equal to out_size.
 * @out_pos:    Current position in the output buffer. This must not exceed
 *              out_size.
 * @out_size:   Size of the output buffer
 *
 * Only the contents of the output buffer from out[out_pos] onward, and
 * the variables in_pos and out_pos are modified by the XZ code.
 */
struct xz_buf {
	const uint8_t *in;
	size_t in_pos;
	size_t in_size;

	uint8_t *out;
	size_t out_pos;
	size_t out_size;
};

/**
 * struct xz_dec - Opaque type to hold the XZ decoder state
 */
struct xz_dec;

/* If no specific decoding mode is requested, enable support for all modes. */
#if !defined(XZ_DEC_SINGLE) && !defined(XZ_DEC_PREALLOC) \
		&& !defined(XZ_DEC_DYNALLOC)
#	define XZ_DEC_SINGLE
#	define XZ_DEC_PREALLOC
#	define XZ_DEC_DYNALLOC
#endif

/*
 * The DEC_IS_foo(mode) macros are used in "if" statements. If only some
 * of the supported modes are enabled, these macros will evaluate to true or
 * false at compile time and thus allow the compiler to omit unneeded code.
 */
#ifdef XZ_DEC_SINGLE
#	define DEC_IS_SINGLE(mode) ((mode) == XZ_SINGLE)
#else
#	define DEC_IS_SINGLE(mode) (false)
#endif

#ifdef XZ_DEC_PREALLOC
#	define DEC_IS_PREALLOC(mode) ((mode) == XZ_PREALLOC)
#else
#	define DEC_IS_PREALLOC(mode) (false)
#endif

#ifdef XZ_DEC_DYNALLOC
#	define DEC_IS_DYNALLOC(mode) ((mode) == XZ_DYNALLOC)
#else
#	define DEC_IS_DYNALLOC(mode) (false)
#endif

#if !defined(XZ_DEC_SINGLE)
#	define DEC_IS_MULTI(mode) (true)
#elif defined(XZ_DEC_PREALLOC) || defined(XZ_DEC_DYNALLOC)
#	define DEC_IS_MULTI(mode) ((mode) != XZ_SINGLE)
#else
#	define DEC_IS_MULTI(mode) (false)
#endif

/*
 * If any of the BCJ filter decoders are wanted, define XZ_DEC_BCJ.
 * XZ_DEC_BCJ is used to enable generic support for BCJ decoders.
 */
#ifndef XZ_DEC_BCJ
#	if defined(XZ_DEC_X86) || defined(XZ_DEC_POWERPC) \
			|| defined(XZ_DEC_IA64) || defined(XZ_DEC_ARM) \
			|| defined(XZ_DEC_ARM) || defined(XZ_DEC_ARMTHUMB) \
			|| defined(XZ_DEC_SPARC)
#		define XZ_DEC_BCJ
#	endif
#endif

/*
 * Allocate memory for LZMA2 decoder. xz_dec_lzma2_reset() must be used
 * before calling xz_dec_lzma2_run().
 */
XZ_EXTERN struct xz_dec_lzma2 *xz_dec_lzma2_create(enum xz_mode mode,
						   uint32_t dict_max);

/*
 * Decode the LZMA2 properties (one byte) and reset the decoder. Return
 * XZ_OK on success, XZ_MEMLIMIT_ERROR if the preallocated dictionary is not
 * big enough, and XZ_OPTIONS_ERROR if props indicates something that this
 * decoder doesn't support.
 */
XZ_EXTERN enum xz_ret xz_dec_lzma2_reset(struct xz_dec_lzma2 *s,
					 uint8_t props);

/* Decode raw LZMA2 stream from b->in to b->out. */
XZ_EXTERN enum xz_ret xz_dec_lzma2_run(struct xz_dec_lzma2 *s,
				       struct xz_buf *b);

/* Free the memory allocated for the LZMA2 decoder. */
XZ_EXTERN void xz_dec_lzma2_end(struct xz_dec_lzma2 *s);

#ifdef XZ_DEC_BCJ
/*
 * Allocate memory for BCJ decoders. xz_dec_bcj_reset() must be used before
 * calling xz_dec_bcj_run().
 */
XZ_EXTERN struct xz_dec_bcj *xz_dec_bcj_create(bool_t single_call);

/*
 * Decode the Filter ID of a BCJ filter. This implementation doesn't
 * support custom start offsets, so no decoding of Filter Properties
 * is needed. Returns XZ_OK if the given Filter ID is supported.
 * Otherwise XZ_OPTIONS_ERROR is returned.
 */
XZ_EXTERN enum xz_ret xz_dec_bcj_reset(struct xz_dec_bcj *s, uint8_t id);

/*
 * Decode raw BCJ + LZMA2 stream. This must be used only if there actually is
 * a BCJ filter in the chain. If the chain has only LZMA2, xz_dec_lzma2_run()
 * must be called directly.
 */
XZ_EXTERN enum xz_ret xz_dec_bcj_run(struct xz_dec_bcj *s,
				     struct xz_dec_lzma2 *lzma2,
				     struct xz_buf *b);

/* Free the memory allocated for the BCJ filters. */
#define xz_dec_bcj_end(s) free(s)
#endif

#endif
