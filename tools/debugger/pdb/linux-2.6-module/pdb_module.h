
#ifndef __PDB_MODULE_H_
#define __PDB_MODULE_H_

#include "../pdb_caml_xen.h"

#define PDB_OPCODE_PAUSE  1

#define PDB_OPCODE_ATTACH 2
typedef struct pdb_op_attach
{
    u32  domain;
} pdb_op_attach_t, *pdb_op_attach_p;

#define PDB_OPCODE_DETACH 3

#define PDB_OPCODE_RD_REGS 4
typedef struct pdb_op_rd_regs
{
    u32 reg[GDB_REGISTER_FRAME_SIZE];
} pdb_op_rd_regs_t, *pdb_op_rd_regs_p;

#define PDB_OPCODE_WR_REG 5
typedef struct pdb_op_wr_reg
{
    u32 reg;
    u32 value;
} pdb_op_wr_reg_t, *pdb_op_wr_reg_p;

#define PDB_OPCODE_RD_MEM 6
typedef struct pdb_op_rd_mem_req
{
    u32 address;
    u32 length;
} pdb_op_rd_mem_req_t, *pdb_op_rd_mem_req_p;

typedef struct pdb_op_rd_mem_resp
{
    u32 address;
    u32 length;
    u8  data[1024];
} pdb_op_rd_mem_resp_t, *pdb_op_rd_mem_resp_p;

#define PDB_OPCODE_WR_MEM 7
typedef struct pdb_op_wr_mem
{
    u32 address;
    u32 length;
    u8  data[1024];                                             /* arbitrary */
} pdb_op_wr_mem_t, *pdb_op_wr_mem_p;

#define PDB_OPCODE_CONTINUE 8
#define PDB_OPCODE_STEP     9

#define PDB_OPCODE_SET_BKPT 10
#define PDB_OPCODE_CLR_BKPT 11
typedef struct pdb_op_bkpt
{
    u32 address;
    u32 length;
} pdb_op_bkpt_t, *pdb_op_bkpt_p;


typedef struct 
{
    u8   operation;       /* PDB_OPCODE_???      */
    u32  process;
    union
    {
        pdb_op_attach_t     attach;
        pdb_op_wr_reg_t     wr_reg;
        pdb_op_rd_mem_req_t rd_mem;
        pdb_op_wr_mem_t     wr_mem;
        pdb_op_bkpt_t       bkpt;
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
        pdb_op_rd_regs_t     rd_regs;
        pdb_op_rd_mem_resp_t rd_mem;
    } u;
} pdb_response_t, *pdb_response_p;


DEFINE_RING_TYPES(pdb, pdb_request_t, pdb_response_t);

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

