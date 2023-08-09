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

typedef int8_t  __s8;
typedef uint8_t __u8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

#endif /* __XEN_LINUX_COMPAT_H__ */
