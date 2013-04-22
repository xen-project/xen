#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom_decompress_unsafe.h"

#include "../../xen/common/bunzip2.c"

int xc_try_bzip2_decode(
    struct xc_dom_image *dom, void **blob, size_t *size)
{
    return xc_dom_decompress_unsafe(bunzip2, dom, blob, size);
}
