
#ifndef __ASM_XEN_DRIVER_UTIL_H__
#define __ASM_XEN_DRIVER_UTIL_H__

#include <linux/config.h>
#include <linux/vmalloc.h>

extern struct vm_struct *prepare_vm_area(unsigned long size);

#endif /* __ASM_XEN_DRIVER_UTIL_H__ */
