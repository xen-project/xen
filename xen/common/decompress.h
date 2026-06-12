#ifndef DECOMPRESS_H
#define DECOMPRESS_H

#ifdef __XEN__

#include <xen/decompress.h>
#include <xen/init.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/xmalloc.h>

#define malloc(s) xmalloc_bytes(s)
#define free(p) xfree(p)

#else

#undef __init /* tools/libs/guest/xg_private.h has its own one */
#define __init
#define __initdata

#endif

#define large_malloc(s) malloc(s)
#define large_free(p) free(p)

#endif /* DECOMPRESS_H */
