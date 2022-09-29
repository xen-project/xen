/******************************************************************************
 * iocap.h
 * 
 * Architecture-specific per-domain I/O capabilities.
 */

#ifndef __X86_IOCAP_H__
#define __X86_IOCAP_H__

#include <xen/sched.h>
#include <xen/rangeset.h>

#include <asm/p2m.h>

#define ioports_access_permitted(d, s, e)               \
    rangeset_contains_range((d)->arch.ioport_caps, s, e)

#define cache_flush_permitted(d)                        \
    (!rangeset_is_empty((d)->iomem_caps) ||             \
     !rangeset_is_empty((d)->arch.ioport_caps))

static inline int ioports_permit_access(struct domain *d, unsigned long s,
                                        unsigned long e)
{
    bool flush = cache_flush_permitted(d);
    int ret = rangeset_add_range(d->arch.ioport_caps, s, e);

    if ( !ret && !is_iommu_enabled(d) && !flush )
        /* See comment in iomem_permit_access(). */
        memory_type_changed(d);

    return ret;
}

static inline int ioports_deny_access(struct domain *d, unsigned long s,
                                      unsigned long e)
{
    int ret = rangeset_remove_range(d->arch.ioport_caps, s, e);

    if ( !ret && !is_iommu_enabled(d) && !cache_flush_permitted(d) )
        /* See comment in iomem_deny_access(). */
        memory_type_changed(d);

    return ret;
}

#endif /* __X86_IOCAP_H__ */
