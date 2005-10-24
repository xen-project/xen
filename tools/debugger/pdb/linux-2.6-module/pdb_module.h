
#ifndef __PDB_MODULE_H_
#define __PDB_MODULE_H_

#include "../pdb_caml_xen.h"

#define PDB_OPCODE_PAUSE  1

#define PDB_OPCODE_ATTACH 2
typedef struct pdb_op_attach
{
    uint32_t  domain;
} pdb_op_attach_t, *pdb_op_attach_p;

#define PDB_OPCODE_DETACH 3

#define PDB_OPCODE_RD_REG 4
typedef struct pdb_op_rd_reg
{
    uint32_t reg;
    uint32_t value;
} pdb_op_rd_reg_t, *pdb_op_rd_reg_p;

#define PDB_OPCODE_RD_REGS 5
typedef struct pdb_op_rd_regs
{
    uint32_t reg[GDB_REGISTER_FRAME_SIZE];
} pdb_op_rd_regs_t, *pdb_op_rd_regs_p;

#define PDB_OPCODE_WR_REG 6
typedef struct pdb_op_wr_reg
{
    uint32_t reg;
    uint32_t value;
} pdb_op_wr_reg_t, *pdb_op_wr_reg_p;

#define PDB_OPCODE_RD_MEM 7
typedef struct pdb_op_rd_mem_req
{
    uint32_t address;
    uint32_t length;
} pdb_op_rd_mem_req_t, *pdb_op_rd_mem_req_p;

typedef struct pdb_op_rd_mem_resp
{
    uint32_t address;
    uint32_t length;
    uint8_t  data[1024];
} pdb_op_rd_mem_resp_t, *pdb_op_rd_mem_resp_p;

#define PDB_OPCODE_WR_MEM 8
typedef struct pdb_op_wr_mem
{
    uint32_t address;
    uint32_t length;
    uint8_t  data[1024];                                             /* arbitrary */
} pdb_op_wr_mem_t, *pdb_op_wr_mem_p;

#define PDB_OPCODE_CONTINUE 9
#define PDB_OPCODE_STEP     10

#define PDB_OPCODE_SET_BKPT 11
#define PDB_OPCODE_CLR_BKPT 12
typedef struct pdb_op_bkpt
{
    uint32_t address;
    uint32_t length;
} pdb_op_bkpt_t, *pdb_op_bkpt_p;

#define PDB_OPCODE_SET_WATCHPT 13
#define PDB_OPCODE_CLR_WATCHPT 14
#define PDB_OPCODE_WATCHPOINT  15
typedef struct pdb_op_watchpt
{
#define BWC_DEBUG 1
#define BWC_INT3  3
#define BWC_WATCH        100                         /* pdb: watchpoint page */
#define BWC_WATCH_STEP   101                  /* pdb: watchpoint single step */
#define BWC_WATCH_WRITE  102
#define BWC_WATCH_READ   103
#define BWC_WATCH_ACCESS 104
    uint32_t type;
    uint32_t address;
    uint32_t length;
} pdb_op_watchpt_t, *pdb_op_watchpt_p;


typedef struct 
{
    uint8_t   operation;       /* PDB_OPCODE_???      */
    uint32_t  process;
    union
    {
        pdb_op_attach_t     attach;
        pdb_op_rd_reg_t     rd_reg;
        pdb_op_wr_reg_t     wr_reg;
        pdb_op_rd_mem_req_t rd_mem;
        pdb_op_wr_mem_t     wr_mem;
        pdb_op_bkpt_t       bkpt;
        pdb_op_watchpt_t    watchpt;
    } u;
} pdb_request_t, *pdb_request_p;

 

#define PDB_RESPONSE_OKAY   0
#define PDB_RESPONSE_ERROR -1

typedef struct {
    uint8_t  operation;       /* copied from request */
    uint32_t domain;          
    uint32_t process;
    int16_t  status;          /* PDB_RESPONSE_???    */
    union
    {
        pdb_op_rd_reg_t      rd_reg;
        pdb_op_rd_regs_t     rd_regs;
        pdb_op_rd_mem_resp_t rd_mem;
    } u;
} pdb_response_t, *pdb_response_p;


DEFINE_RING_TYPES(pdb, pdb_request_t, pdb_response_t);


/* from access_process_vm */
#define PDB_MEM_READ  0
#define PDB_MEM_WRITE 1

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

