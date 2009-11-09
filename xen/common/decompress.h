#include <xen/config.h>
#include <xen/cache.h>
#include <xen/decompress.h>
#include <xen/init.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/xmalloc.h>

#define STATIC
#define INIT __init

static void(*__initdata error)(const char *);
#define set_error_fn(x) error = x;

#define malloc xmalloc_bytes
#define free xfree

#define large_malloc xmalloc_bytes
#define large_free xfree
