/******************************************************************************
 * xenolinux_block_test.c
 * 
 */
#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/delay.h>

#include <asm/hypervisor-ifs/block.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>

/******************************************************************/

static struct proc_dir_entry *bdt;
static blk_ring_req_entry_t meta;
static char * data;

static int proc_read_bdt(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
  switch (meta.operation)
  {
    case XEN_BLOCK_READ :
    case XEN_BLOCK_WRITE :
    {
      return proc_dump_block(page, start, off, count, eof, data);
    }
    case XEN_BLOCK_DEBUG :
    {
      return proc_dump_debug(page, start, off, count, eof, data);
    }
    default :
    {
      printk(KERN_ALERT 
	     "block device test error: unknown operation [%c]\n",
	     meta.operation);
      return -EINVAL;
    }
  }
}

int proc_dump_debug(char *page, char **start, off_t off,
		    int count, int *eof, void *data)
{
  char header[100];
  char dump[1024];

  sprintf (header, "Block Device Test: Debug Dump\n\n");
  
  sprintf (dump, "%s\n", meta.buffer);
  
  if (data)
  {
    kfree(data);
  }

  strncpy (page, dump, count);
  return strlen(page);
}

int proc_dump_block(char *page, char **start, off_t off,
		    int count, int *eof, void *data)
{
  char header[100];
  char dump[1024];
  char temp[100];
  int loop;

  sprintf (header, "Block Device Test\n\n%s  blk num: %ld 0x%lx;  size: %d 0x%x;  device: 0x%x\n",
	   meta.operation == XEN_BLOCK_WRITE ? "write" : "read",
	   meta.block_number, meta.block_number,
	   meta.block_size, meta.block_size,
	   meta.device);
  
  sprintf (dump, "%s", header);

  if (meta.buffer)
  {
    for (loop = 0; loop < 100; loop++)
    {
      int i = meta.buffer[loop];
    
      if (loop % 8 == 0)
      {
	sprintf (temp, "[%2d] ", loop);
	strcat(dump, temp);
      }
      else if (loop % 2 == 0)
      {
	strcat(dump, " ");
      }

      sprintf (temp, " 0x%02x", i & 255);
      strcat(dump, temp);
      if ((loop + 1) % 8 == 0)
      {
	strcat(dump, "\n");
      }
    }
    strcat(dump, "\n\n");
  }
  
  if (data)
  {
    kfree(data);
  }

  strncpy (page, dump, count);
  return strlen(page);
}

int proc_write_bdt(struct file *file, const char *buffer,
		   unsigned long count, void *data)
{
  char *local = kmalloc((count + 1) * sizeof(char), GFP_KERNEL);
  char  opcode;
  int  block_number = 0;
  int  block_size = 0;
  int  device = 0;

  if (copy_from_user(local, buffer, count))
  {
    return -EFAULT;
  }
  local[count] = '\0';

  sscanf(local, "%c %i %i %i", 
	 &opcode, &block_number, &block_size, &device);

  if (data)
  {
    kfree(data);
  }

  if (opcode == 'r' || opcode == 'R')
  {
    meta.operation = XEN_BLOCK_READ;
  }
  else if (opcode == 'w' || opcode == 'W')
  {
    meta.operation = XEN_BLOCK_WRITE;
  }
  else if (opcode == 'd' || opcode == 'D')
  {
    meta.operation = XEN_BLOCK_DEBUG;
    block_size = 10000;
  }
  else if (opcode == 'c' || opcode == 'C')
  {
    xv_disk_t *xvd;
    int loop;

    meta.operation = XEN_BLOCK_SEG_CREATE;
    data = kmalloc (sizeof(xv_disk_t), GFP_KERNEL);
    if (data == NULL)
    {
      kfree(local);
      return -ENOMEM;
    }
    
    xvd = (xv_disk_t *)data;
    xvd->mode = XEN_DISK_READ_WRITE;
    xvd->domain = block_number;
    xvd->segment = block_size;
    xvd->ext_count = device;
    for (loop = 0; loop < xvd->ext_count; loop++)
    {
      xvd->extents[loop].disk = block_number + 1;                  /* random */
      xvd->extents[loop].offset = block_size + 1;
      xvd->extents[loop].size = device + 1;
    }
  }
  else
  {
    printk(KERN_ALERT 
	   "block device test error: unknown opcode [%c]\n", opcode);
    return -EINVAL;
  }

  if (data == NULL)
  {
    data = kmalloc(block_size * sizeof(char), GFP_KERNEL);
    if (data == NULL)
    {
      kfree(local);
      return -ENOMEM;
    }
  }

  meta.block_number = block_number;
  meta.block_size   = block_size;
  meta.device       = device;
  meta.buffer       = data;

  /* submit request */
  hypervisor_request(0, meta.operation, meta.buffer, 
		     meta.block_number, meta.block_size,
		     meta.device, 
		     (struct gendisk *) NULL);
  HYPERVISOR_block_io_op();
  mdelay(1000); /* should wait for a proper acknowledgement/response. */

  kfree(local);
  return count;
}
			 

static int __init init_module(void)
{
  int return_value = 0;

  /* create proc entry */
  bdt = create_proc_entry("bdt", 0644, NULL);
  if (bdt == NULL)
  {
    return_value = -ENOMEM;
    goto error;
  }
  bdt->data       = NULL;
  bdt->read_proc  = proc_read_bdt;
  bdt->write_proc = proc_write_bdt;
  bdt->owner      = THIS_MODULE;

  memset(&meta, 0, sizeof(meta));
  
  /* success */
  printk(KERN_ALERT "XenoLinux Block Device Test installed\n");
  return 0;

 error:
  return return_value;
}

static void __exit cleanup_module(void)
{
  if (data)
  {
    kfree(data);
  }
  printk(KERN_ALERT "XenoLinux Block Device Test uninstalled\n");
}

module_init(init_module);
module_exit(cleanup_module);
