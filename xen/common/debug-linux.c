#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <hypervisor-ifs/dom0_ops.h>

#include "debug-linux.h"

/* 
 * linux specific pdb stuff 
 */

/*
  static inline struct task_struct *find_task_by_pid(int pid)
  {
    struct task_struct *p, **htable = &pidhash[pid_hashfn(pid)];

    for(p = *htable; p && p->pid != pid; p = p->pidhash_next) ;
    return p;
  }
*/

/* read a byte from a process */
u_char pdb_linux_get_value (int domain, int pid, unsigned long addr)
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
    printk ("error: couldn't find process 0x%x in domain %d\n", pid, domain);
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
