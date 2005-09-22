
#ifndef __ASM_XEN_DRIVER_UTIL_H__
#define __ASM_XEN_DRIVER_UTIL_H__

#include <linux/config.h>
#include <linux/vmalloc.h>

/* Allocate/destroy a 'vmalloc' VM area. */
extern struct vm_struct *alloc_vm_area(unsigned long size);
extern void free_vm_area(struct vm_struct *area);

/* Lock an area so that PTEs are accessible in the current address space. */
extern void lock_vm_area(struct vm_struct *area);
extern void unlock_vm_area(struct vm_struct *area);

#endif /* __ASM_XEN_DRIVER_UTIL_H__ */
