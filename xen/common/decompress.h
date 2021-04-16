#ifdef __XEN__

#include <xen/cache.h>
#include <xen/decompress.h>
#include <xen/init.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/xmalloc.h>

#define STATIC static
#define INIT __init
#define INITDATA __initdata

#define malloc xmalloc_bytes
#define free xfree

#define large_malloc xmalloc_bytes
#define large_free xfree

#else

#define STATIC static
#define INIT
#define INITDATA

#undef __init /* tools/libs/guest/xg_private.h has its own one */
#define __init
#define __initdata

#define large_malloc malloc
#define large_free free

#endif
