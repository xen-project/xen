#include <asm/pdb.h>

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
static inline unsigned long machine_to_phys(int domain, unsigned long machine)
{
  unsigned long phys;
  pdb_get_values(domain, (u_char *) &phys,
		 (unsigned long) machine_to_phys_mapping + (machine >> PAGE_SHIFT) * 4,
		 sizeof(phys));
  phys = (phys << PAGE_SHIFT) | (machine & ~PAGE_MASK);
  return phys;
}


#define pidhash_addr 0xc018f260UL

#define task_struct_mm_offset  0x2c
#define task_struct_pid_offset 0x7c
#define task_struct_pidhash_next_offset 0xb0
#define mm_struct_pgd_offset   0x0c

extern u_char pdb_linux_get_value (int domain, int pid, unsigned long addr);
