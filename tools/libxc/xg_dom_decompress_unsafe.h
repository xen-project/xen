#include "xc_dom.h"

typedef int decompress_fn(unsigned char *inbuf, unsigned int len,
                          int (*fill)(void*, unsigned int),
                          int (*flush)(void*, unsigned int),
                          unsigned char *outbuf, unsigned int *posp,
                          void (*error)(const char *x));

int xc_dom_decompress_unsafe(
    decompress_fn fn, struct xc_dom_image *dom, void **blob, size_t *size)
    __attribute__((visibility("internal")));

int xc_try_bzip2_decode(struct xc_dom_image *dom, void **blob, size_t *size)
    __attribute__((visibility("internal")));
int xc_try_lzma_decode(struct xc_dom_image *dom, void **blob, size_t *size)
    __attribute__((visibility("internal")));
int xc_try_lzo1x_decode(struct xc_dom_image *dom, void **blob, size_t *size)
    __attribute__((visibility("internal")));
int xc_try_xz_decode(struct xc_dom_image *dom, void **blob, size_t *size)
    __attribute__((visibility("internal")));
