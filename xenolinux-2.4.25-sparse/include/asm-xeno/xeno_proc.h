
#ifndef __ASM_XENO_PROC_H__
#define __ASM_XENO_PROC_H__

#include <linux/config.h>
#include <linux/proc_fs.h>

extern struct proc_dir_entry *create_xeno_proc_entry(
    const char *name, mode_t mode);
extern void remove_xeno_proc_entry(
    const char *name);

#endif /* __ASM_XENO_PROC_H__ */
