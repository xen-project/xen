#include <linux/config.h>
#include <linux/version.h>

#include <linux/mm.h>
#include <linux/module.h>

#include <xen/platform-compat.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
static int system_state = 1;
EXPORT_SYMBOL(system_state);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
size_t strcspn(const char *s, const char *reject)
{
        const char *p;
        const char *r;
        size_t count = 0;

        for (p = s; *p != '\0'; ++p) {
                for (r = reject; *r != '\0'; ++r) {
                        if (*p == *r)
                                return count;
                }
                ++count;
        }

        return count;
}
EXPORT_SYMBOL(strcspn);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
/*
 * Map a vmalloc()-space virtual address to the physical page frame number.
 */
unsigned long vmalloc_to_pfn(void * vmalloc_addr)
{
        return page_to_pfn(vmalloc_to_page(vmalloc_addr));
}
EXPORT_SYMBOL(vmalloc_to_pfn);
#endif
