/******************************************************************************
 * dom_mem_ops.h
 *
 * Header file supporting domain related memory operations. N.B. keep in sync
 * with xen version. 
 *
 * Copyright (c) 2003, B Dragovic
 */

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|_PAGE_ACCESSED)
#define BALLOON_DEFLATE_OP   0
#define BALLOON_INFLATE_OP   1

typedef struct balloon_deflate_op {
    unsigned long   size;
    unsigned long   * pages;
} balloon_def_op_t;

typedef struct balloon_inflate_op {
    unsigned long   size;
    unsigned long   * pages;
} balloon_inf_op_t;

typedef struct dom_mem_ops
{
    unsigned int op;
    union
    {
        balloon_def_op_t balloon_deflate;
        balloon_inf_op_t balloon_inflate;
    }u;
} dom_mem_op_t;
