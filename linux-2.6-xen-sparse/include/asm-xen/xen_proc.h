
#ifndef __ASM_XEN_PROC_H__
#define __ASM_XEN_PROC_H__

#include <linux/config.h>
#include <linux/proc_fs.h>

extern struct proc_dir_entry *create_xen_proc_entry(
	const char *name, mode_t mode);
extern void remove_xen_proc_entry(
	const char *name);

#endif /* __ASM_XEN_PROC_H__ */

/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
