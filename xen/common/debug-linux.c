#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <hypervisor-ifs/dom0_ops.h>
#include <asm/pdb.h>

/* 
 * linux specific pdb stuff 
 */

/* from linux/sched.h */
#define PIDHASH_SZ (4096 >> 2)
#define pid_hashfn(x)	((((x) >> 8) ^ (x)) & (PIDHASH_SZ - 1))

/* from asm-xeno/pgtable-2level.h */
#define PGDIR_SHIFT	22
#define PTRS_PER_PGD	1024

/* from asm-xeno/page.h */
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


/* adapted from asm-xeno/page.h */
static inline unsigned long machine_to_phys(domid_t domain, 
                                            unsigned long machine)
{
  unsigned long phys;
  pdb_get_values(domain, (u_char *) &phys,
		 (unsigned long) machine_to_phys_mapping + 
                 (machine >> PAGE_SHIFT) * 4,
		 sizeof(phys));
  phys = (phys << PAGE_SHIFT) | (machine & ~PAGE_MASK);
  return phys;
}


#define pidhash_addr 0xc018f260UL

#define task_struct_mm_offset  0x2c
#define task_struct_pid_offset 0x7c
#define task_struct_pidhash_next_offset 0xb0
#define mm_struct_pgd_offset   0x0c

/*
  static inline struct task_struct *find_task_by_pid(int pid)
  {
    struct task_struct *p, **htable = &pidhash[pid_hashfn(pid)];

    for(p = *htable; p && p->pid != pid; p = p->pidhash_next) ;
    return p;
  }
*/

/* read a byte from a process */
u_char pdb_linux_get_value(domid_t domain, int pid, unsigned long addr)
{
  u_char result = 0;
  unsigned long task_struct_p, mm_p, pgd, task_struct_pid;
  unsigned long l2tab, page;

  /* find the task_struct of the given process */
  pdb_get_values(domain, (u_char *) &task_struct_p, 
		 pidhash_addr + pid_hashfn(pid) * 4,
		 sizeof(task_struct_p));

  /* find the correct task struct */
  while (task_struct_p != (unsigned long)NULL)
  {
    pdb_get_values(domain, (u_char *) &task_struct_pid, 
		   task_struct_p + task_struct_pid_offset,
		   sizeof(task_struct_pid));
    if (task_struct_pid == pid)
    {
      break;
    }
    
    pdb_get_values(domain, (u_char *) &task_struct_p, 
		   task_struct_p + task_struct_pidhash_next_offset,
		   sizeof(task_struct_p));
  }
  if (task_struct_p == (unsigned long)NULL)
  {
    /* oops */
    printk ("error: couldn't find process 0x%x in domain %llu\n", pid, domain);
    return 0;
  }

  /* get the mm_struct within the task_struct */
  pdb_get_values(domain, (u_char *) &mm_p, 
		 task_struct_p + task_struct_mm_offset,
		 sizeof(mm_p));
  /* get the page global directory (cr3) within the mm_struct */
  pdb_get_values(domain, (u_char *) &pgd, 
		 mm_p + mm_struct_pgd_offset,
		 sizeof(pgd));

  /* get the l2 table entry */
  pdb_get_values(domain, (u_char *) &l2tab, 
		 pgd + (addr >> PGDIR_SHIFT) * 4,
		 sizeof(l2tab));
  l2tab = (unsigned long)__va(machine_to_phys(domain, l2tab) & PAGE_MASK);

  /* get the page table entry */
  pdb_get_values(domain, (u_char *) &page,
		 l2tab + ((addr & L1_PAGE_BITS) >> PAGE_SHIFT) * 4,
		 sizeof(page));
  page = (unsigned long)__va(machine_to_phys(domain, page) & PAGE_MASK);

  /* get the byte */
  pdb_get_values(domain, (u_char *) &result, page + (addr & ~PAGE_MASK),
		 sizeof(result));

  return result;
}
