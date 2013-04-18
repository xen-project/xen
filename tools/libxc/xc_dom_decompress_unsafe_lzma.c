#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom_decompress_unsafe.h"

#include "../../xen/common/unlzma.c"

int xc_try_lzma_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(unlzma, dom, blob, size);
}
