
#ifndef __ASM_XEN_PROC_H__
#define __ASM_XEN_PROC_H__

#include <linux/proc_fs.h>

extern struct proc_dir_entry *create_xen_proc_entry(
	const char *name, mode_t mode);
extern void remove_xen_proc_entry(
	const char *name);

#endif /* __ASM_XEN_PROC_H__ */
