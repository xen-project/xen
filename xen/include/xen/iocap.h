/******************************************************************************
 * iocap.h
 * 
 * Per-domain I/O capabilities.
 */

#ifndef __XEN_IOCAP_H__
#define __XEN_IOCAP_H__

#include <xen/sched.h>
#include <xen/rangeset.h>
#include <asm/iocap.h>
#include <asm/p2m.h>

static inline int iomem_permit_access(struct domain *d, unsigned long s,
                                      unsigned long e)
{
    bool flush = cache_flush_permitted(d);
    int ret = rangeset_add_range(d->iomem_caps, s, e);

    if ( !ret && !is_iommu_enabled(d) && !flush )
        /*
         * Only flush if the range(s) are empty before this addition and
         * IOMMU is not enabled for the domain, otherwise it makes no
         * difference for effective cache attribute calculation purposes.
         */
        memory_type_changed(d);

    return ret;
}

static inline int iomem_deny_access(struct domain *d, unsigned long s,
                                    unsigned long e)
{
    int ret = rangeset_remove_range(d->iomem_caps, s, e);

    if ( !ret && !is_iommu_enabled(d) && !cache_flush_permitted(d) )
        /*
         * Only flush if the range(s) are empty after this removal and
         * IOMMU is not enabled for the domain, otherwise it makes no
         * difference for effective cache attribute calculation purposes.
         */
        memory_type_changed(d);

    return ret;
}

#define iomem_access_permitted(d, s, e)                 \
    rangeset_contains_range((d)->iomem_caps, s, e)

#define irq_permit_access(d, i)                         \
    rangeset_add_singleton((d)->irq_caps, i)
#define irq_deny_access(d, i)                           \
    rangeset_remove_singleton((d)->irq_caps, i)
#define irqs_permit_access(d, s, e)                     \
    rangeset_add_range((d)->irq_caps, s, e)
#define irqs_deny_access(d, s, e)                       \
    rangeset_remove_range((d)->irq_caps, s, e)
#define irq_access_permitted(d, i)                      \
    rangeset_contains_singleton((d)->irq_caps, i)

#define pirq_access_permitted(d, i) ({                  \
    struct domain *d__ = (d);                           \
    int irq__ = domain_pirq_to_irq(d__, i);             \
    irq__ > 0 && irq_access_permitted(d__, irq__)       \
    ? irq__ : 0;                                        \
})

#endif /* __XEN_IOCAP_H__ */
