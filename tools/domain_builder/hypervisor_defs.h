/******************************************************************************
 * hypervisor_defs.h
 * 
 * This needs to be kept in sync with Xen's pagetable update interface!
 * 
 * Copyright (c) 2002-2003, Keir Fraser & Boris Dragovic 
 */

/* taken from include/hypervisor-ifs/hypervisor-if.h */
typedef struct
{
/*
 * PGREQ_XXX: specified in least-significant bits of 'ptr' field. All requests 
 * specify relevent PTE or PT address in 'ptr'. Normal requests specify update 
 * value in 'value'. Extended requests specify command in least 8 bits of 
 * 'value'.
 */
    unsigned long ptr, val; /* *ptr = val */
} page_update_request_t;

/* A normal page-table update request. */
#define PGREQ_NORMAL           0
#define PGREQ_MPT_UPDATE 1
/* An extended command. */
#define PGREQ_EXTENDED_COMMAND 2
/* Announce a new top-level page table. */
#define PGEXT_PIN_L1_TABLE      0
#define PGEXT_PIN_L2_TABLE      1
#define PGEXT_PIN_L3_TABLE      2
#define PGEXT_PIN_L4_TABLE      3
#define PGEXT_UNPIN_TABLE       4
#define PGEXT_NEW_BASEPTR       5
#define PGEXT_TLB_FLUSH         6
#define PGEXT_INVLPG            7
#define PGEXT_CMD_MASK        255
#define PGEXT_CMD_SHIFT         8
