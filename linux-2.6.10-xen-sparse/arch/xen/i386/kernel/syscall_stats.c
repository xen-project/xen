/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2005 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: syscall_stats.c
 *      Author: Rolf Neugebauer (rolf.neugebauer@intel.com)
 *        Date: Mar 2005
 * 
 * Description: add a proc interface to get per system call stats
 */


#include <linux/config.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/unistd.h>

unsigned long syscall_stats[NR_syscalls];
static unsigned char foobar[4];

unsigned long c_do_page_fault;
unsigned long c_minor_page_fault;
unsigned long c_major_page_fault;

/* a write just resests the counter */
static ssize_t syscall_write(struct file *f, const  char *data,
                             size_t size, loff_t  *pos)
{
    printk("resetting syscall stats\n");
    memset(&syscall_stats, 0, sizeof(syscall_stats));
    c_do_page_fault = 0;
    c_minor_page_fault = 0;
    c_major_page_fault = 0;
    return size;
}

static int show_syscall(struct seq_file *m, void *v)
{
    int i;
    for ( i=0; i<NR_syscalls; i++ )
    {
        seq_printf(m, "%lu ", syscall_stats[i]);
    }
    seq_printf(m, "\n");
    seq_printf(m, "%lu %lu %lu\n", c_do_page_fault,
               c_minor_page_fault, c_major_page_fault);
    
    return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
    return *pos == 0 ? foobar : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
    ++*pos;
    return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

static struct seq_operations syscall_op = {
    start:  c_start,
    next:   c_next,
    stop:   c_stop,
    show:   show_syscall,
};

static int syscall_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &syscall_op);
}

static struct file_operations proc_syscall_operations = {
    open:           syscall_open,
    read:           seq_read,
    write:          syscall_write,
    llseek:         seq_lseek,
    release:        seq_release,
};


static struct proc_dir_entry *entry;

static int __init syscall_stats_init(void)
{
    printk("Initialising syscall stats.\n");

    entry = create_proc_entry("syscalls", 0777, NULL);
    if (entry)
        entry->proc_fops = &proc_syscall_operations;
    else
        printk("Unable to create /proc/syscalls.\n");
    return 0;
}
subsys_initcall(syscall_stats_init);
