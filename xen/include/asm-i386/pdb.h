
/*
 * pervasive debugger
 *
 * alex ho
 * 2004
 * university of cambridge computer laboratory
 */


#ifndef __PDB_H__
#define __PDB_H__

#include <asm/ptrace.h>
#include <xeno/list.h>

extern int pdb_initialized;
extern int pdb_com_port;
extern int pdb_high_bit;

extern void initialize_pdb(void);
extern int pdb_set_values (int domain, u_char *buffer, 
			   unsigned long addr, int length);
extern int pdb_get_values (int domain, u_char *buffer,
			   unsigned long addr, int length);

extern int pdb_handle_exception(int exceptionVector,
				struct pt_regs *xen_regs);


struct pdb_breakpoint
{
    struct list_head list;
    unsigned long address;
};
extern void pdb_bkpt_add (unsigned long address);
extern struct pdb_breakpoint* pdb_bkpt_search (unsigned long address);
extern void pdb_bkpt_remove_ptr (struct pdb_breakpoint *bkpt);
extern int pdb_bkpt_remove (unsigned long address);

#endif  /* __PDB_H__ */
