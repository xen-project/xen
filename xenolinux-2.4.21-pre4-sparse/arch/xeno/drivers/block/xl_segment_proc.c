/*
 * xl_segment_proc.c
 * 
 * XenoLinux virtual disk proc interface .
 */


#include <linux/config.h>
#include <linux/module.h>

#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>

#include <asm/hypervisor-ifs/block.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>

static struct proc_dir_entry *vhd;
xv_disk_t xvd;

extern atomic_t xlblk_control_count;                           /* xl_block.c */

int hypervisor_request(void *          id,
                       int             operation,
                       char *          buffer,
                       unsigned long   block_number,
                       unsigned short  block_size,
                       kdev_t          device,
		       struct gendisk *gd);

/******************************************************************/

static int proc_read_vhd(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
  return 0;
}

#define isdelim(c) \
  (c==' '||c==','||c=='\n'||c=='\r'||c=='\t'||c==':'||c=='('||c==')' ? 1 : 0)

char *get_string(char *string)                          /* a bit like strtok */
{
  static char *temp;
  int loop = 0;

  if (string != NULL)	
    temp = string;
  else
    string = temp;

 try_again:

  while (!isdelim(string[loop]))
  {
    if (string[loop] == '\0')
      return NULL;
    loop++;
  }

  string[loop] = '\0';	
  temp = (string + loop + 1);

  if (loop == 0)
  {
    string = temp;
    goto try_again;
  }

  return string;
}


#define isdigit(c) (c >= '0' && c <= '9' ? 1 : 0)
unsigned long to_number(char *string)                                /* atoi */
{
  unsigned long value = 0;

  if (string == NULL) return 0;

  while (!isdigit(*string) && *string != '\0') string++;

  while (isdigit(*string))
  {
    value = value * 10 + (*string - '0');
    string++;
  }

  return value;
}

static int proc_write_vhd(struct file *file, const char *buffer,
			  unsigned long count, void *data)
{
  char *local = kmalloc((count + 1) * sizeof(char), GFP_KERNEL);
  char *string;
  int loop;
  int counter;
  xv_disk_t xvd;

  memset (&xvd, 0, sizeof(xvd));

  if (copy_from_user(local, buffer, count))
  {
    return -EFAULT;
  }
  local[count] = '\0';

  string = get_string(local);                             /* look for Domain */
  if (string == NULL)                                        /* empty string */
  {
    return count;
  }
  if (*string != 'd' && *string != 'D')
  {
    printk (KERN_ALERT 
	    "error: domain specifier missing [%s]. should be \"domain\".\n",
	    string);
    return count;
  }

  string = get_string(NULL);                                /* domain number */
  if (string == NULL)
  {
    printk (KERN_ALERT "error: domain number missing\n");
    return count;
  }
  xvd.domain = (int) to_number(string);

  string = get_string(NULL);
  if (string && (strcmp(string, "RO") == 0 || strcmp(string, "ro") == 0))
  {
    xvd.mode = XEN_DISK_READ_ONLY;
  }
  else if (string && (strcmp(string, "RW") == 0 || strcmp(string, "rw") == 0))
  {
    xvd.mode = XEN_DISK_READ_WRITE;
  }
  else
  {
    printk (KERN_ALERT 
	    "error: bad mode [%s]. should be \"rw\" or \"ro\".\n",
	    string);
    return count;
  }

  string = get_string(NULL);                             /* look for Segment */
  if (string == NULL || (*string != 's' && *string != 'S'))
  {
    printk (KERN_ALERT 
	    "error: segment specifier missing [%s]. should be \"segment\".\n",
	    string);
    return count;
  }

  string = get_string(NULL);                               /* segment number */
  if (string == NULL)
  {
    printk (KERN_ALERT "error: segment number missing\n");
    return count;
  }
  xvd.segment = (int) to_number(string);

  string = get_string(NULL);                             /* look for Extents */
  if (string == NULL || (*string != 'e' && *string != 'E'))
  {
    printk (KERN_ALERT 
	    "error: extents specifier missing [%s]. should be \"extents\".\n",
	    string);
    return count;
  }

  string = get_string(NULL);                            /* number of extents */
  if (string == NULL)
  {
    printk (KERN_ALERT "error: number of extents missing\n");
    return count;
  }
  xvd.ext_count = (int) to_number(string);

  /* ignore parenthesis */

  for (loop = 0; loop < xvd.ext_count; loop++)
  {
    string = get_string(NULL);                              /* look for Disk */
    if (string == NULL || (*string != 'd' && *string != 'D'))
    {
      printk (KERN_ALERT 
	      "hmm, extent disk specifier missing [%s]. should be \"disk\".\n",
	      string);
      return count;
    }
    string = get_string(NULL);                                /* disk number */
    if (string == NULL)
    {
      printk (KERN_ALERT "error: disk number missing\n");
      return count;
    }
    xvd.extents[loop].disk = (int) to_number(string);

    string = get_string(NULL);                            /* look for Offset */
    if (string == NULL || (*string != 'o' && *string != 'O'))
    {
      printk (KERN_ALERT 
	      "error: disk offset missing [%s]. should be \"offset\".\n",
	    string);
      return count;
    }
    string = get_string(NULL);                                     /* offset */
    if (string == NULL)
    {
      printk (KERN_ALERT "error: offset missing\n");
      return count;
    }
    xvd.extents[loop].offset =  to_number(string);

    string = get_string(NULL);                              /* look for Size */
    if (string == NULL || (*string != 's' && *string != 'S'))
    {
      printk (KERN_ALERT 
	      "error: extent size missing [%s]. should be \"size\".\n",
	    string);
      return count;
    }
    string = get_string(NULL);                                       /* size */
    if (string == NULL)
    {
      printk (KERN_ALERT "error: extent size missing\n");
      return count;
    }
    xvd.extents[loop].size =  to_number(string);
  }

  {
    /* get lock xlblk_control_lock     */
    counter = atomic_read(&xlblk_control_count);
    atomic_inc(&xlblk_control_count);
    /* release lock xlblk_control_lock */
  }
  if (hypervisor_request (NULL, XEN_BLOCK_SEG_CREATE, (char *)&xvd,
			  0, 0, (kdev_t) 0,
			  (struct gendisk *)NULL))
    BUG();
  HYPERVISOR_block_io_op();

  while (atomic_read(&xlblk_control_count) != counter) barrier();

  return count;
}

/******************************************************************/

int __init xlseg_proc_init(void)
{
  vhd = create_proc_entry("xeno/dom0/vhd", 0644, NULL);
  if (vhd == NULL)
  {
    panic ("xlseg_init: unable to create vhd proc entry\n");
  }
  vhd->data       = NULL;
  vhd->read_proc  = proc_read_vhd;
  vhd->write_proc = proc_write_vhd;
  vhd->owner      = THIS_MODULE;

  memset(&xvd, 0, sizeof(xvd));

  printk(KERN_ALERT "XenoLinux Virtual Disk Device Monitor installed\n");
  return 0;
}

static void __exit xlseg_proc_cleanup(void)
{
  printk(KERN_ALERT "XenoLinux Virtual Disk Device Monitor uninstalled\n");
}

#ifdef MODULE
module_init(xlseg_proc_init);
module_exit(xlseg_proc_cleanup);
#endif
