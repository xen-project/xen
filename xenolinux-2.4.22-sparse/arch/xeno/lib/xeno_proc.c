
#include <linux/config.h>
#include <linux/proc_fs.h>

static struct proc_dir_entry *xeno_base;

struct proc_dir_entry *create_xeno_proc_entry(const char *name, mode_t mode)
{
    if ( xeno_base == NULL )
        if ( (xeno_base = proc_mkdir("xeno", &proc_root)) == NULL )
            panic("Couldn't create /proc/xeno");
    return create_proc_entry(name, mode, xeno_base);
}

void remove_xeno_proc_entry(const char *name)
{
    remove_proc_entry(name, xeno_base);
}
