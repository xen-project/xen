
#include "xl_block.h"
#include <linux/blk.h>
#include <linux/cdrom.h>
#include <linux/genhd.h>
#include <linux/seq_file.h>
#include <asm/xeno_proc.h>

static struct proc_dir_entry *info_pde;

static void *info_start(struct seq_file *s, loff_t *ppos)
{
    struct gendisk *gp;
    loff_t pos = *ppos;
    int major;

    if ( pos == 0 )
        seq_puts(s, "major minor start_sector  num_sectors name\n\n");

    for ( major = 0; major < MAX_BLKDEV; major++ )
    {
        if ( (gp = get_gendisk(MKDEV(major, 0))) != 0 )
            if ( !pos-- )
                return gp;
    }

    return NULL;
}

static void *info_next(struct seq_file *s, void *v, loff_t *ppos)
{
    ++*ppos;
    return info_start(s, ppos);
}

static void info_stop(struct seq_file *s, void *v)
{
}

static int info_show(struct seq_file *s, void *v)
{
    struct gendisk *gp = v;
    char buf[64];
    int n, disk;
    
    for ( n = 0; n < (gp->nr_real << gp->minor_shift); n++ ) 
    {
        disk = n >> gp->minor_shift;
        if ( gp->part[n].nr_sects != 0 ) 
        {
            seq_printf(s, "%5d %5d %12ld %12ld %s\n",
                       gp->major, n,
                       gp->part[n].start_sect,
                       gp->part[n].nr_sects,
                       disk_name(gp, n, buf));
        }
        else if ( ((disk << gp->minor_shift) == n) &&
                  ((((xl_disk_t *)gp->real_devices)[disk].capacity) != 0) )
        {
            seq_printf(s, "%5d %5d %12d %12ld %s\n",
                       gp->major, n, 0, 
                       ((xl_disk_t *)gp->real_devices)[disk].capacity,
                       disk_name(gp, n, buf));
        }
    }
    
    return 0;
}

static struct seq_operations info_op = {
    .start          = info_start,
    .next           = info_next,
    .stop           = info_stop,
    .show           = info_show,
};

static int info_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &info_op);
}

static struct file_operations proc_info_operations = 
{
    open:           info_open,
    read:           seq_read,
    llseek:         seq_lseek,
    release:        seq_release,
};

int __init info_init(void)
{
    info_pde = create_xeno_proc_entry("blkdev_info", 0444);
    if ( info_pde == NULL )
        panic ("Couldn't create /proc/xeno/blkdev_info");

    info_pde->data       = NULL;
    info_pde->proc_fops  = &proc_info_operations;
    info_pde->owner      = THIS_MODULE;

    return 0;
}

static void __exit info_exit(void)
{
    if ( info_pde == NULL ) return;
    remove_xeno_proc_entry("blkdev_info");
    info_pde = NULL;
}

module_init(info_init);
module_exit(info_exit);
