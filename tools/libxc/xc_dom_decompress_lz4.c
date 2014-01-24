#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <endian.h>
#include <stdint.h>

#include "xg_private.h"
#include "xc_dom_decompress.h"

#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define likely(a) a
#define unlikely(a) a

static inline uint_fast16_t le16_to_cpup(const unsigned char *buf)
{
    return buf[0] | (buf[1] << 8);
}

static inline uint_fast32_t le32_to_cpup(const unsigned char *buf)
{
    return le16_to_cpup(buf) | ((uint32_t)le16_to_cpup(buf + 2) << 16);
}

#include "../../xen/include/xen/lz4.h"
#include "../../xen/common/decompress.h"

#ifndef __MINIOS__

#include "../../xen/common/lz4/decompress.c"

#define ARCHIVE_MAGICNUMBER 0x184C2102

int xc_try_lz4_decode(
	struct xc_dom_image *dom, void **blob, size_t *psize)
{
	int ret = -1;
	unsigned char *inp = *blob, *output, *outp;
	ssize_t size = *psize - 4;
	size_t out_len, dest_len, chunksize;
	const char *msg;

	if (size < 4) {
		msg = "input too small";
		goto exit_0;
	}

	out_len = get_unaligned_le32(inp + size);
	if (xc_dom_kernel_check_size(dom, out_len)) {
		msg = "Decompressed image too large";
		goto exit_0;
	}

	output = malloc(out_len);
	if (!output) {
		msg = "Could not allocate output buffer";
		goto exit_0;
	}
	outp = output;

	chunksize = get_unaligned_le32(inp);
	if (chunksize == ARCHIVE_MAGICNUMBER) {
		inp += 4;
		size -= 4;
	} else {
		msg = "invalid header";
		goto exit_2;
	}

	for (;;) {
		if (size < 4) {
			msg = "missing data";
			goto exit_2;
		}
		chunksize = get_unaligned_le32(inp);
		if (chunksize == ARCHIVE_MAGICNUMBER) {
			inp += 4;
			size -= 4;
			continue;
		}
		inp += 4;
		size -= 4;
		if (chunksize > size) {
			msg = "insufficient input data";
			goto exit_2;
		}

		dest_len = out_len - (outp - output);
		ret = lz4_decompress_unknownoutputsize(inp, chunksize, outp,
				&dest_len);
		if (ret < 0) {
			msg = "decoding failed";
			goto exit_2;
		}

		ret = -1;
		outp += dest_len;
		size -= chunksize;

		if (size == 0)
		{
			*blob = output;
			*psize = out_len;
			return 0;
		}

		if (size < 0) {
			msg = "data corrupted";
			goto exit_2;
		}

		inp += chunksize;
	}

exit_2:
	free(output);
exit_0:
	DOMPRINTF("LZ4 decompression error: %s\n", msg);
	return ret;
}

#else /* __MINIOS__ */

#include "../../xen/common/unlz4.c"

int xc_try_lz4_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unlz4, dom, blob, size);
}

#endif
