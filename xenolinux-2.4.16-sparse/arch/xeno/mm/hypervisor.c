/******************************************************************************
 * xeno/mm/hypervisor.c
 * 
 * Update page tables via the hypervisor.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <linux/config.h>
#include <asm/hypervisor.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#define QUEUE_SIZE 1
static page_update_request_t update_queue[QUEUE_SIZE];

void queue_l1_entry_update(unsigned long ptr, unsigned long val)
{
    update_queue[0].ptr = ptr + start_info.phys_base;
    update_queue[0].val = val;
    flush_page_update_queue();
}

void queue_l2_entry_update(unsigned long ptr, unsigned long val)
{
    update_queue[0].ptr = ptr + start_info.phys_base;
    update_queue[0].val = val;
    flush_page_update_queue();
}

void queue_baseptr_create(unsigned long ptr)
{
    update_queue[0].ptr = PGREQ_ADD_BASEPTR;
    update_queue[0].val = ptr + start_info.phys_base;
    flush_page_update_queue();
}

void queue_baseptr_remove(unsigned long ptr)
{
    update_queue[0].ptr = PGREQ_REMOVE_BASEPTR;
    update_queue[0].val = ptr + start_info.phys_base;
    flush_page_update_queue();
}

void queue_tlb_flush(void)
{
    /* nothing */
}

void queue_tlb_flush_one(unsigned long ptr)
{
    /* nothing */
}

void flush_page_update_queue(void)
{
    HYPERVISOR_pt_update(update_queue, 1);
}
