
/*
 * pervasive debugger
 * www.cl.cam.ac.uk/netos/pdb
 *
 * alex ho
 * 2004
 * university of cambridge computer laboratory
 *
 * linux specific pdb stuff 
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <public/dom0_ops.h>
#include <asm/pdb.h>

/* from linux/sched.h */
#define PIDHASH_SZ (4096 >> 2)
#define pid_hashfn(x)	((((x) >> 8) ^ (x)) & (PIDHASH_SZ - 1))

/* from asm-xen/pgtable-2level.h */
#define PGDIR_SHIFT	22
#define PTRS_PER_PGD	1024

/* from asm-xen/page.h */
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#define __PAGE_OFFSET		(0xC0000000)
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define __pa(x)			((unsigned long)(x)-PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long)(x)+PAGE_OFFSET))

/* from debug.h */
#define ENTRIES_PER_L1_PAGETABLE 1024
#define L1_PAGE_BITS ( (ENTRIES_PER_L1_PAGETABLE - 1) << PAGE_SHIFT )

void pdb_linux_process_details (unsigned long cr3, int pid, char *buffer);

/* adapted from asm-xen/page.h */
static inline unsigned long machine_to_phys(unsigned long cr3,
                                            unsigned long machine)
{
  unsigned long phys;
  pdb_get_values((u_char *) &phys, sizeof(phys), cr3,
		 (unsigned long) machine_to_phys_mapping + 
                 (machine >> PAGE_SHIFT) * 4);
  phys = (phys << PAGE_SHIFT) | (machine & ~PAGE_MASK);
  return phys;
}

unsigned long pdb_pidhash_addr         = 0xc01971e0UL;
unsigned long pdb_init_task_union_addr = 0xc0182000UL;


unsigned int task_struct_mm_offset           = 0x2c;
unsigned int task_struct_next_task_offset    = 0x48;
unsigned int task_struct_pid_offset          = 0x7c;
unsigned int task_struct_pidhash_next_offset = 0xb0;
unsigned int task_struct_comm_offset         = 0x23e;
unsigned int task_struct_comm_length         = 0x10;

unsigned int mm_struct_pgd_offset            = 0x0c;

/*
 * find the task structure of a process (pid)
 * given the cr3 of the guest os.
 */
unsigned long pdb_linux_pid_task_struct (unsigned long cr3, int pid)
{
  unsigned long task_struct_p = (unsigned long) NULL;
  unsigned long task_struct_pid;

  /* find the task_struct of the given process */
  pdb_get_values((u_char *) &task_struct_p, sizeof(task_struct_p),
		 cr3, pdb_pidhash_addr + pid_hashfn(pid) * 4);

  /* find the correct task struct */
  while (task_struct_p != (unsigned long)NULL)
  {
    pdb_get_values((u_char *) &task_struct_pid, sizeof(task_struct_pid),
		   cr3, task_struct_p + task_struct_pid_offset);
    if (task_struct_pid == pid)
    {
      break;
    }

    pdb_get_values((u_char *) &task_struct_p, sizeof(task_struct_p),
		   cr3, task_struct_p + task_struct_pidhash_next_offset);
  }
  if (task_struct_p == (unsigned long) NULL)
  {
    /* oops */
    printk ("pdb error: couldn't find process 0x%x (0x%lx)\n", pid, cr3);
  }

  return task_struct_p;
}

/*
 * find the ptbr of a process (pid)
 * given the cr3 of the guest os.
 */
unsigned long pdb_linux_pid_ptbr (unsigned long cr3, int pid)
{
  unsigned long task_struct_p;
  unsigned long mm_p, pgd;

  task_struct_p = pdb_linux_pid_task_struct(cr3, pid);
  if (task_struct_p == (unsigned long) NULL)
  {
    return (unsigned long) NULL;
  }

  /* get the mm_struct within the task_struct */
  pdb_get_values((u_char *) &mm_p, sizeof(mm_p),
		 cr3, task_struct_p + task_struct_mm_offset);
  /* get the page global directory (cr3) within the mm_struct */
  pdb_get_values((u_char *) &pgd, sizeof(pgd),
		 cr3, mm_p + mm_struct_pgd_offset);

  return pgd;
}



/* read a byte from a process 
 *
 * in: pid: process id
 *     cr3: ptbr for the process' domain
 *     addr: address to read
 */

u_char pdb_linux_get_value(int pid, unsigned long cr3, unsigned long addr)
{
  u_char result = 0;
  unsigned long pgd;
  unsigned long l2tab, page;

  /* get the process' pgd */
  pgd = pdb_linux_pid_ptbr(cr3, pid);

  /* get the l2 table entry */
  pdb_get_values((u_char *) &l2tab, sizeof(l2tab),
		 cr3, pgd + (addr >> PGDIR_SHIFT) * 4);
  l2tab = (unsigned long)__va(machine_to_phys(cr3, l2tab) & PAGE_MASK);

  /* get the page table entry */
  pdb_get_values((u_char *) &page, sizeof(page),
		 cr3, l2tab + ((addr & L1_PAGE_BITS) >> PAGE_SHIFT) * 4);
  page = (unsigned long)__va(machine_to_phys(cr3, page) & PAGE_MASK);

  /* get the byte */
  pdb_get_values((u_char *) &result, sizeof(result),
		 cr3, page + (addr & ~PAGE_MASK));

  return result;
}

void pdb_linux_get_values(char *buffer, int length, unsigned long address,
			  int pid, unsigned long cr3)
{
    int loop;

    /* yes, this can be optimized... a lot */
    for (loop = 0; loop < length; loop++)
    {
        buffer[loop] = pdb_linux_get_value(pid, cr3, address + loop);
    }
}

 
void pdb_linux_set_value(int pid, unsigned long cr3, unsigned long addr,
			 u_char *value)
{
    unsigned long pgd;
    unsigned long l2tab, page;
 
    /* get the process' pgd */
    pgd = pdb_linux_pid_ptbr(cr3, pid);
 
    /* get the l2 table entry */
    pdb_get_values((u_char *) &l2tab, sizeof(l2tab),
		   cr3, pgd + (addr >> PGDIR_SHIFT) * 4);
    l2tab = (unsigned long)__va(machine_to_phys(cr3, l2tab) & PAGE_MASK);
 
    /* get the page table entry */
    pdb_get_values((u_char *) &page, sizeof(page),
		   cr3, l2tab + ((addr & L1_PAGE_BITS) >> PAGE_SHIFT) * 4);
    page = (unsigned long)__va(machine_to_phys(cr3, page) & PAGE_MASK);
 
    /* set the byte */
    pdb_set_values(value, sizeof(u_char), cr3, page + (addr & ~PAGE_MASK));
}
 
void pdb_linux_set_values(char *buffer, int length, unsigned long address,
			  int pid, unsigned long cr3)
{
    int loop;
 
    /* it's difficult to imagine a more inefficient algorithm */
    for (loop = 0; loop < length; loop++)
    {
        pdb_linux_set_value(pid, cr3, address + loop, &buffer[loop * 2]);
    }
}

/**********************************************************************/

/*
 * return 1 if is the virtual address is in the operating system's
 * address space, else 0 
 */
int pdb_linux_address_space (unsigned long addr)
{
    return (addr > PAGE_OFFSET);
}

/* get a list of at most "max" processes
 * return: number of threads found
 *
 *   init_task -> init_task_union.task
 *   while (next_task != init_task) {}
 */
int pdb_linux_process_list (unsigned long cr3, int array[], int max)
{
  unsigned long task_p, next_p;
  int pid;
  int count = 0;

  /* task_p = init_task->next_task  */
  pdb_get_values((u_char *) &task_p, sizeof(task_p),
		 cr3, pdb_init_task_union_addr + task_struct_next_task_offset);
  
  while (task_p != pdb_init_task_union_addr)
  {
      pdb_get_values((u_char *) &pid, sizeof(pid),
		     cr3, task_p + task_struct_pid_offset);

      array[count % max] = pid;
      count++;

      pdb_get_values((u_char *) &next_p, sizeof(next_p),
		     cr3, task_p + task_struct_next_task_offset);
      task_p = next_p;
  }

  return count;
}

/*
 * get additional details about a particular process
 */
void pdb_linux_process_details (unsigned long cr3, int pid, char *buffer)
{
  unsigned long task_struct_p;

  task_struct_p = pdb_linux_pid_task_struct(cr3, pid);

  pdb_get_values((u_char *) buffer, task_struct_comm_length,
		 cr3, task_struct_p + task_struct_comm_offset);
  return;
}

