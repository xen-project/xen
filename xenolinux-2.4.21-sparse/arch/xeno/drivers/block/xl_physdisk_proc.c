/* We stuff the domain number into the proc_dir_entry data pointer. */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/errno.h>
#include <linux/slab.h>
#include <asm/hypervisor-ifs/block.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>

#include "xl_block.h"

extern int xenolinux_control_msg(int operration, char *buffer, int size);
extern unsigned short xldev_to_physdev(kdev_t xldev);

dev_t physdev_to_xldev(unsigned short physdev)
{
    switch (physdev & XENDEV_TYPE_MASK) {
    case XENDEV_IDE:
        if ( (physdev & XENDEV_IDX_MASK) < XLIDE_DEVS_PER_MAJOR) {
	    return MKDEV(XLIDE_MAJOR_0,
			 (physdev & XENDEV_IDX_MASK) << XLIDE_PARTN_SHIFT);
	} else if ( (physdev & XENDEV_IDX_MASK) < (XLIDE_DEVS_PER_MAJOR * 2)) {
	    return MKDEV(XLIDE_MAJOR_1,
			 (physdev & XENDEV_IDX_MASK) << XLIDE_PARTN_SHIFT);
	}
	break;
    case XENDEV_SCSI:
	return MKDEV(XLSCSI_MAJOR,
		     (physdev & XENDEV_IDX_MASK) << XLSCSI_PARTN_SHIFT);
    case XENDEV_VIRTUAL:
	return MKDEV(XLVIRT_MAJOR,
		     (physdev & XENDEV_IDX_MASK) << XLVIRT_PARTN_SHIFT);
    }
    printk(KERN_ALERT "Unrecognised xl device: %x\n", physdev);
    BUG();
    return -1;
}

static ssize_t proc_read_phd(struct file *file, char *buff, size_t size,
			     loff_t * off)
{
    physdisk_probebuf_t *buf;
    int res;
    struct proc_dir_entry *pde;
    int x;

    if (size != sizeof(physdisk_probebuf_t))
	return -EINVAL;

    buf = kmalloc(sizeof(physdisk_probebuf_t), GFP_KERNEL);
    if (!buf)
	return -ENOMEM;

    pde = file->f_dentry->d_inode->u.generic_ip;
    buf->domain = (int) pde->data;

    /* The offset reported by lseek and friends doesn't have to be in
       bytes, and it's marginally easier to say that it's in records, so
       that's what we do. */
    buf->start_ind = *off;
    res = xenolinux_control_msg(XEN_BLOCK_PHYSDEV_PROBE, (void *) buf,
				sizeof(physdisk_probebuf_t));
    *off += buf->n_aces;

    if (res)
	res = -EINVAL;
    else {
	for (x = 0; x < buf->n_aces; x++)
	    buf->entries[x].device =
		physdev_to_xldev(buf->entries[x].device);
	res = sizeof(physdisk_probebuf_t);
	if (copy_to_user(buff, buf, sizeof(physdisk_probebuf_t))) {
	    res = -EFAULT;
	}
    }
    kfree(buf);
    return res;
}

static int proc_write_phd(struct file *file, const char *buffer,
			  size_t count, loff_t * ignore)
{
    char *local;
    int res;
    xp_disk_t *xpd;
    struct proc_dir_entry *pde;

    if (count != sizeof(xp_disk_t))
	return -EINVAL;

    local = kmalloc(count + 1, GFP_KERNEL);
    if (!local)
	return -ENOMEM;
    if (copy_from_user(local, buffer, count)) {
	res = -EFAULT;
	goto out;
    }

    xpd = (xp_disk_t *) local;

    pde = file->f_dentry->d_inode->u.generic_ip;
    xpd->domain = (int) pde->data;
    xpd->device = xldev_to_physdev(xpd->device);

    res = xenolinux_control_msg(XEN_BLOCK_PHYSDEV_GRANT, local, count);
    if (res == 0)
	res = count;
    else
	res = -EINVAL;
  out:
    kfree(local);
    return res;
}

struct file_operations dom0_phd_fops = {
  read:proc_read_phd,
  write:proc_write_phd
};
