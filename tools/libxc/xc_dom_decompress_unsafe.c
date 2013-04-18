#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom_decompress_unsafe.h"

static struct xc_dom_image *unsafe_dom;
static unsigned char *output_blob;
static unsigned int output_size;

static void unsafe_error(const char *msg)
{
    xc_dom_panic(unsafe_dom->xch, XC_INVALID_KERNEL, "%s", msg);
}

static int unsafe_flush(void *src, unsigned int size)
{
    void *n = realloc(output_blob, output_size + size);
    if (!n)
        return -1;
    output_blob = n;

    memcpy(&output_blob[output_size], src, size);
    output_size += size;
    return size;
}

int xc_dom_decompress_unsafe(
    decompress_fn fn, struct xc_dom_image *dom, void **blob, size_t *size)
{
    int ret;

    unsafe_dom = dom;
    output_blob = NULL;
    output_size = 0;

    ret = fn(dom->kernel_blob, dom->kernel_size, NULL, unsafe_flush, NULL, NULL, unsafe_error);

    if (ret)
        free(output_blob);
    else {
        *blob = output_blob;
        *size = output_size;
    }

    return ret;
}
