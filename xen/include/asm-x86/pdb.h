
/*
 * pervasive debugger
 * www.cl.cam.ac.uk/netos/pdb
 *
 * alex ho
 * 2004
 * university of cambridge computer laboratory
 */


#ifndef __PDB_H__
#define __PDB_H__

#include <asm/ptrace.h>
#include <xen/list.h>
#include <public/dom0_ops.h>
#include <public/xen.h>                   /* for domain id */

extern int pdb_initialized;
extern int pdb_com_port;
extern int pdb_high_bit;
extern int pdb_page_fault_possible;
extern int pdb_page_fault_scratch;
extern int pdb_page_fault;

extern void initialize_pdb(void);

/* Get/set values from generic debug interface. */
extern int pdb_set_values(u_char *buffer, int length,
                          unsigned long cr3, unsigned long addr);
extern int pdb_get_values(u_char *buffer, int length,
                          unsigned long cr3, unsigned long addr);

/* External entry points. */
extern int pdb_handle_exception(int exceptionVector,
				struct pt_regs *xen_regs);
extern void pdb_do_debug(dom0_op_t *op);

/* PDB Context. */
struct pdb_context
{
    int valid;
    int domain;
    int process;
    int system_call;              /* 0x01 break on enter, 0x02 break on exit */
    unsigned long ptbr;
};
extern struct pdb_context pdb_ctx;

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

/* Temporary Linux specific definitions */
extern int pdb_system_call;
extern unsigned char pdb_system_call_enter_instr;    /* original enter instr */
extern unsigned char pdb_system_call_leave_instr;     /* original next instr */
extern unsigned long pdb_system_call_next_addr;      /* instr after int 0x80 */
extern unsigned long pdb_system_call_eflags_addr;   /* saved eflags on stack */

unsigned long pdb_linux_pid_ptbr (unsigned long cr3, int pid);
void pdb_linux_get_values(char *buffer, int length, unsigned long address,
			  int pid, unsigned long cr3);
void pdb_linux_set_values(char *buffer, int length, unsigned long address,
			  int pid, unsigned long cr3);
void pdb_linux_syscall_enter_bkpt (struct pt_regs *regs, long error_code,
				   trap_info_t *ti);
void pdb_linux_syscall_exit_bkpt (struct pt_regs *regs, 
				  struct pdb_context *pdb_ctx);

#endif  /* __PDB_H__ */
