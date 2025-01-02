/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <asm/idt.h>
#include <asm/page.h>

idt_entry_t __section(".bss.page_aligned") __aligned(PAGE_SIZE)
    bsp_idt[X86_IDT_VECTORS];
