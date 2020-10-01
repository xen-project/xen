#ifdef __MINIOS__
# include "xg_dom_decompress_unsafe.h"
#endif

int xc_try_lz4_decode(struct xc_dom_image *dom, void **blob, size_t *size);

