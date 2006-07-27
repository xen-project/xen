/******************************************************************************
 * iocap.h
 * 
 * Architecture-specific per-domain I/O capabilities.
 */

#ifndef __IA64_IOCAP_H__
#define __IA64_IOCAP_H__

extern int ioports_permit_access(struct domain *d,
                                 unsigned long s, unsigned long e);
extern int ioports_deny_access(struct domain *d,
                               unsigned long s, unsigned long e);

#define ioports_access_permitted(d, s, e)               \
    rangeset_contains_range((d)->arch.ioport_caps, s, e)

#endif /* __IA64_IOCAP_H__ */
