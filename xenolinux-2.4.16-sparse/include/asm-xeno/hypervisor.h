/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/ptrace.h>

/* arch/xeno/kernel/setup.c */
union start_info_union
{
    start_info_t start_info;
    char padding[512];
};
extern union start_info_union start_info_union;
#define start_info (start_info_union.start_info)

/* arch/xeno/kernel/hypervisor.c */
void do_hypervisor_callback(struct pt_regs *regs);

/* arch/xeno/mm/hypervisor.c */
/*
 * NB. ptr values should be fake-physical. 'vals' should be alread
 * fully adjusted (ie. for start_info.phys_base).
 */
void queue_l1_entry_update(unsigned long ptr, unsigned long val);
void queue_l2_entry_update(unsigned long ptr, unsigned long val);
void queue_baseptr_create(unsigned long ptr);
void queue_baseptr_remove(unsigned long ptr);
void queue_tlb_flush(void);
void queue_tlb_flush_one(unsigned long ptr);
void flush_page_update_queue(void);

#endif /* __HYPERVISOR_H__ */
