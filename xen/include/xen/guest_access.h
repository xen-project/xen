/******************************************************************************
 * guest_access.h
 * 
 * Copyright (x) 2006, K A Fraser
 */

#ifndef __XEN_GUEST_ACCESS_H__
#define __XEN_GUEST_ACCESS_H__

#include <asm/guest_access.h>
#include <xen/types.h>
#include <public/xen.h>

#define copy_to_guest(hnd, ptr, nr)                     \
    copy_to_guest_offset(hnd, 0, ptr, nr)

#define copy_from_guest(ptr, hnd, nr)                   \
    copy_from_guest_offset(ptr, hnd, 0, nr)

#define clear_guest(hnd, nr)                            \
    clear_guest_offset(hnd, 0, nr)

#define __copy_to_guest(hnd, ptr, nr)                   \
    __copy_to_guest_offset(hnd, 0, ptr, nr)

#define __copy_from_guest(ptr, hnd, nr)                 \
    __copy_from_guest_offset(ptr, hnd, 0, nr)

#define __clear_guest(hnd, nr)                          \
    __clear_guest_offset(hnd, 0, nr)

char *safe_copy_string_from_guest(XEN_GUEST_HANDLE(char) u_buf,
                                  size_t size, size_t max_size);

#endif /* __XEN_GUEST_ACCESS_H__ */
