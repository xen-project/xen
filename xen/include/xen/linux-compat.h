/******************************************************************************
 * linux-compat.h
 *
 * Container for types and other definitions use in Linux (and hence in files
 * we "steal" from there), but which shouldn't be used (anymore) in normal Xen
 * files.
 */

#ifndef __XEN_LINUX_COMPAT_H__
#define __XEN_LINUX_COMPAT_H__

#include <xen/types.h>

typedef int8_t  s8, __s8;
typedef uint8_t __u8;
typedef int16_t s16, __s16;
typedef uint16_t __u16;
typedef int32_t s32, __s32;
typedef uint32_t __u32;
typedef int64_t s64, __s64;
typedef uint64_t __u64;

typedef paddr_t phys_addr_t;

#define __ffs(x) (ffsl(x) - 1UL)

#endif /* __XEN_LINUX_COMPAT_H__ */
