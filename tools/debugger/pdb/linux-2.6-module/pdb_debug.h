
#ifndef __PDB_DEBUG_H_
#define __PDB_DEBUG_H_

/* debugger.c */
void pdb_initialize_bwcpoint (void);
int pdb_suspend (struct task_struct *target);
int pdb_resume (struct task_struct *target);
int pdb_read_register (struct task_struct *target, pdb_op_rd_reg_p op);
int pdb_read_registers (struct task_struct *target, pdb_op_rd_regs_p op);
int pdb_write_register (struct task_struct *target, pdb_op_wr_reg_p op);
int pdb_read_memory (struct task_struct *target, pdb_op_rd_mem_req_p req, 
                     pdb_op_rd_mem_resp_p resp);
int pdb_write_memory (struct task_struct *target, pdb_op_wr_mem_p op);
int pdb_access_memory (struct task_struct *target, unsigned long address, 
                       void *buffer, int length, int write);
int pdb_continue (struct task_struct *target);
int pdb_step (struct task_struct *target);

int pdb_insert_memory_breakpoint (struct task_struct *target, 
                                  unsigned long address, u32 length);
int pdb_remove_memory_breakpoint (struct task_struct *target,
                                  unsigned long address, u32 length);
int pdb_insert_watchpoint (struct task_struct *target,
                           pdb_op_watchpt_p watchpt);
int pdb_remove_watchpoint (struct task_struct *target,
                           pdb_op_watchpt_p watchpt);

int pdb_exceptions_notify (struct notifier_block *self, unsigned long val,
                           void *data);

/* module.c */
void pdb_send_response (pdb_response_t *response);

#endif


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

