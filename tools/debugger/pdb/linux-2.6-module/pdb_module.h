
#ifndef __XEN_PDB_H_
#define __XEN_PDB_H_

#include "../pdb_caml_xen.h"

#define PDB_OPCODE_ATTACH 1
#define PDB_OPCODE_DETACH 2

#define PDB_OPCODE_RD_REGS 3
typedef struct pdb_op_rd_regs
{
    u32 reg[GDB_REGISTER_FRAME_SIZE];
} pdb_op_rd_regs_t, *pdb_op_rd_regs_p;

#define PDB_OPCODE_WR_REG 4
typedef struct pdb_op_wr_reg
{
    u32 reg;
    u32 value;
} pdb_op_wr_reg_t, *pdb_op_wr_reg_p;

typedef struct 
{
    u8   operation;       /* PDB_OPCODE_???      */
    u32  domain;
    u32  process;
    union
    {
        pdb_op_wr_reg_t  wr_reg;
    } u;
} pdb_request_t, *pdb_request_p;
 

#define PDB_RESPONSE_OKAY   0
#define PDB_RESPONSE_ERROR -1

typedef struct {
    u8   operation;       /* copied from request */
    u32  domain;          
    u32  process;
    s16  status;          /* PDB_RESPONSE_???    */
    union
    {
        pdb_op_rd_regs_t rd_regs;
    } u;
} pdb_response_t, *pdb_response_p;


DEFINE_RING_TYPES(pdb, pdb_request_t, pdb_response_t);


int pdb_attach (int pid);
int pdb_detach (int pid);
int pdb_read_register (int pid, pdb_op_rd_regs_p op);
int pdb_write_register (int pid, pdb_op_wr_reg_p op);


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

