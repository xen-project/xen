/* We stuff the domain number into the proc_dir_entry data pointer. */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/errno.h>
#include <linux/slab.h>
#include <asm/hypervisor-ifs/block.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>

extern int xenolinux_control_msg(int operration, char *buffer, int size);

static ssize_t proc_read_phd(struct file * file, char * buff, size_t size,
			     loff_t * off)
{
  physdisk_probebuf_t *buf;
  int res;
  struct proc_dir_entry *pde;

  if (size != sizeof(physdisk_probebuf_t))
    return -EINVAL;

  buf = kmalloc(sizeof(physdisk_probebuf_t), GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  if (copy_from_user(buf, buff, size)) {
    kfree(buf);
    return -EFAULT;
  }

  pde = file->f_dentry->d_inode->u.generic_ip;
  buf->domain = (int)pde->data;

  /* The offset reported by lseek and friends doesn't have to be in
     bytes, and it's marginally easier to say that it's in records, so
     that's what we do. */
  buf->start_ind = *off;
  res = xenolinux_control_msg(XEN_BLOCK_PHYSDEV_PROBE, (void *)buf,
			      sizeof(physdisk_probebuf_t));
  *off += buf->n_aces;

  if (res)
    res = -EINVAL;
  else {
    res = sizeof(physdisk_probebuf_t);
    if (copy_to_user(buff, buf, sizeof(physdisk_probebuf_t))) {
      res = -EFAULT;
    }
  }
  kfree(buf);
  return res;
}

static int proc_write_phd(struct file *file, const char *buffer,
			  size_t count, loff_t *ignore)
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

  xpd = (xp_disk_t *)local;

  pde = file->f_dentry->d_inode->u.generic_ip;
  xpd->domain = (int)pde->data;

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
  read : proc_read_phd,
  write : proc_write_phd
};
