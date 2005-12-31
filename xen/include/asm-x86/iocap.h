/******************************************************************************
 * iocap.h
 * 
 * Architecture-specific per-domain I/O capabilities.
 */

#ifndef __X86_IOCAP_H__
#define __X86_IOCAP_H__

#define ioport_range_permit(d, s, e)                    \
    rangeset_add_range((d)->arch.ioport_caps, s, e)
#define ioport_range_deny(d, s, e)                      \
    rangeset_remove_range((d)->arch.ioport_caps, s, e)
#define ioport_range_access_permitted(d, s, e)          \
    rangeset_contains_range((d)->arch.ioport_caps, s, e)

#endif /* __X86_IOCAP_H__ */
