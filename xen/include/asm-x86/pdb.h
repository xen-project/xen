
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
#include <hypervisor-ifs/dom0_ops.h>
#include <hypervisor-ifs/hypervisor-if.h>                   /* for domain id */

extern int pdb_initialized;
extern int pdb_com_port;
extern int pdb_high_bit;
extern int pdb_page_fault_possible;
extern int pdb_page_fault_scratch;
extern int pdb_page_fault;

extern void initialize_pdb(void);

/*
 * pdb debug context 
 */
typedef struct pdb_context
{
    int valid;
    int domain;
    int process;
    int system_call;              /* 0x01 break on enter, 0x02 break on exit */
    unsigned long ptbr;
} pdb_context_t, *pdb_context_p;

extern pdb_context_t pdb_ctx;

/* read / write memory */
extern int pdb_read_memory (unsigned long addr, int length, 
			    unsigned char *data, pdb_context_p ctx);
extern int pdb_write_memory (unsigned long addr, int length, 
			     unsigned char *data, pdb_context_p ctx);

extern int pdb_read_page (u_char *buffer, int length,
			  unsigned long cr3, unsigned long addr);
extern int pdb_write_page (u_char *buffer, int length,
			   unsigned long cr3, unsigned long addr);

/* External entry points. */
extern int pdb_handle_exception(int exceptionVector,
				struct pt_regs *xen_regs);
extern int pdb_serial_input(u_char c, struct pt_regs *regs);
extern void pdb_do_debug(dom0_op_t *op);

typedef enum pdb_generic_action
{
  __PDB_GET,
  __PDB_SET,
  __PDB_CLEAR
} pdb_generic_action;

/*
 * breakpoint, watchpoint, & catchpoint
 * note: numbers must match GDB remote serial protocol Z command numbers
 */
enum pdb_bwcpoint_type
{
  PDB_BP_SOFTWARE = 0,
  PDB_BP_HARDWARE = 1,
  PDB_WP_WRITE    = 2,
  PDB_WP_READ     = 3,
  PDB_WP_ACCESS   = 4
};

enum pdb_bwcpoint_action
{
  PDB_BWC_UNKNOWN = 0,                                            /* default */
  PDB_BWC_STOP,         /* stop execution and return control to the debugger */
  PDB_BWC_DELETE                                    /* delete the breakpoint */
};

typedef struct pdb_bwcpoint
{
  struct list_head list;
  unsigned long address;
  int length;
  enum pdb_bwcpoint_type type;                            /* how implemented */
  enum pdb_bwcpoint_type user_type;                    /* what was requested */
  enum pdb_bwcpoint_action action;                         /* action to take */
  pdb_context_t context;

  unsigned char original; /* original value for breakpoint, one byte for x86 */
  char *comments;                                                /* comments */
} pdb_bwcpoint_t, *pdb_bwcpoint_p;

void pdb_bwc_list_add (pdb_bwcpoint_p bwc);
void pdb_bwc_list_remove (pdb_bwcpoint_p bwc);
pdb_bwcpoint_p pdb_bwcpoint_search (unsigned long cr3, unsigned long address);

int pdb_set_breakpoint (pdb_bwcpoint_p bwc);
int pdb_clear_breakpoint (unsigned long address, pdb_context_p ctx);


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

/* tracing */
extern int pdb_trace;
#define PDBTRC(_lvl_, _blahblah_) if (_lvl_ & pdb_trace) {_blahblah_;}
#define PDBTRC2(_lvl_, _blahblah_) \
  if (_lvl_ & pdb_trace) {printk("[%s:%d]",__FILE__,__LINE__); _blahblah_;}

#endif  /* __PDB_H__ */
