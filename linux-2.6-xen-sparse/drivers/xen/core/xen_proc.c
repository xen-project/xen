
#include <linux/config.h>
#include <linux/proc_fs.h>
#include <xen/xen_proc.h>

static struct proc_dir_entry *xen_base;

struct proc_dir_entry *create_xen_proc_entry(const char *name, mode_t mode)
{
	if ( xen_base == NULL )
		if ( (xen_base = proc_mkdir("xen", &proc_root)) == NULL )
			panic("Couldn't create /proc/xen");
	return create_proc_entry(name, mode, xen_base);
}

void remove_xen_proc_entry(const char *name)
{
	remove_proc_entry(name, xen_base);
}
