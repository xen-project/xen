
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
#include <hypervisor-ifs/hypervisor-if.h>                   /* for domain id */

extern int pdb_initialized;
extern int pdb_com_port;
extern int pdb_high_bit;

extern void initialize_pdb(void);

/* Get/set values from generic debug interface. */
extern int pdb_set_values(u_char *buffer, int length,
                          unsigned long cr3, unsigned long addr);
extern int pdb_get_values(u_char *buffer, int length,
                          unsigned long cr3, unsigned long addr);

/* External entry points. */
extern int pdb_handle_exception(int exceptionVector,
				struct pt_regs *xen_regs);
extern int pdb_serial_input(u_char c, struct pt_regs *regs);
extern void pdb_do_debug(dom0_op_t *op);

/* Breakpoints. */
struct pdb_breakpoint
{
    struct list_head list;
    unsigned long address;
    unsigned long cr3;
    domid_t domain;
};
extern void pdb_bkpt_add (unsigned long cr3, unsigned long address);
extern struct pdb_breakpoint* pdb_bkpt_search (unsigned long cr3, 
					       unsigned long address);
extern int pdb_bkpt_remove (unsigned long cr3, unsigned long address);

/* Conversions. */
extern int   hex (char);
extern char *mem2hex (char *, char *, int);
extern char *hex2mem (char *, char *, int);
extern int   hexToInt (char **ptr, int *intValue);

#endif  /* __PDB_H__ */
