/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Configuration of event handling for all CPUs.
 */
#include <asm/idt.h>

DEFINE_PER_CPU_READ_MOSTLY(idt_entry_t *, idt);
