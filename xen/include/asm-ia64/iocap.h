/******************************************************************************
 * iocap.h
 * 
 * Architecture-specific per-domain I/O capabilities.
 */

#ifndef __IA64_IOCAP_H__
#define __IA64_IOCAP_H__

#define ioports_permit_access(d, s, e)                  \
    rangeset_add_range((d)->arch.ioport_caps, s, e)
#define ioports_deny_access(d, s, e)                    \
    rangeset_remove_range((d)->arch.ioport_caps, s, e)
#define ioports_access_permitted(d, s, e)               \
    rangeset_contains_range((d)->arch.ioport_caps, s, e)

#endif /* __IA64_IOCAP_H__ */
