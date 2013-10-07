#ifndef __MINIOS__
# include "xc_dom.h"
#else
# include "xc_dom_decompress_unsafe.h"
#endif

int xc_try_lz4_decode(struct xc_dom_image *dom, void **blob, size_t *size);

