#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <asm/pdb.h>

/* 
 * linux specific pdb stuff 
 */

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


#define pidhash_addr         0xc01971e0UL
#define init_task_union_addr 0xc0182000UL

#define task_struct_mm_offset        0x2c
#define task_struct_next_task_offset 0x48
#define task_struct_pid_offset       0x7c
#define task_struct_pidhash_next_offset 0xb0
#define task_struct_comm_offset      0x23e
#define task_struct_comm_length      0x10

#define mm_struct_pgd_offset         0x0c

/* read a byte from a process */
u_char pdb_linux_get_value(int pid, unsigned long cr3, unsigned long addr)
{
  u_char result = 0;
  unsigned long task_struct_p, mm_p, pgd, task_struct_pid;
  unsigned long l2tab, page;

  /* find the task_struct of the given process */
  pdb_get_values((u_char *) &task_struct_p, sizeof(task_struct_p),
		 cr3, pidhash_addr + pid_hashfn(pid) * 4);

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
  if (task_struct_p == (unsigned long)NULL)
  {
    /* oops */
    printk ("error: pdb couldn't find process 0x%x\n", pid);
    return 0;
  }

  /* get the mm_struct within the task_struct */
  pdb_get_values((u_char *) &mm_p, sizeof(mm_p),
		 cr3, task_struct_p + task_struct_mm_offset);
  /* get the page global directory (cr3) within the mm_struct */
  pdb_get_values((u_char *) &pgd, sizeof(pgd),
		 cr3, mm_p + mm_struct_pgd_offset);

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

/* return 1 if is the virtual address is in the operating system's
   address space, else 0 */
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
		 cr3, init_task_union_addr + task_struct_next_task_offset);
  
  while (task_p != init_task_union_addr)
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

/* get additional details about a particular process:
 */
void pdb_linux_process_details (unsigned long cr3, int pid, char *buffer)
{
  unsigned long task_struct_p, task_struct_pid;

  /* find the task_struct of the given process */
  pdb_get_values((u_char *) &task_struct_p, sizeof(task_struct_p),
		 cr3, pidhash_addr + pid_hashfn(pid) * 4);

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
  if (task_struct_p == (unsigned long)NULL)
  {
    /* oops */
    printk ("error: pdb couldn't find process 0x%x\n", pid);
    return;
  }

  pdb_get_values((u_char *) buffer, task_struct_comm_length,
		 cr3, task_struct_p + task_struct_comm_offset);
  return;
}

