/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef X86_ASM_IDT_H
#define X86_ASM_IDT_H

#include <xen/bug.h>

#include <asm/x86-defns.h>

#define IST_NONE 0
#define IST_MCE  1
#define IST_NMI  2
#define IST_DB   3
#define IST_DF   4
#define IST_MAX  4

typedef union {
    struct {
        uint64_t a, b;
    };
    struct {
        uint16_t addr0;
        uint16_t cs;
        uint8_t  ist; /* :3, 5 bits rsvd, but this yields far better code. */
        uint8_t  type:4, s:1, dpl:2, p:1;
        uint16_t addr1;
        uint32_t addr2;
        /* 32 bits rsvd. */
    };
} idt_entry_t;

extern idt_entry_t bsp_idt[X86_IDT_VECTORS];
extern idt_entry_t *idt_tables[];

/*
 * Set the Interrupt Stack Table used by a particular IDT entry.  Typically
 * used on a live IDT, so volatile to disuade clever optimisations.
 */
static inline void set_ist(volatile idt_entry_t *idt, unsigned int ist)
{
    /* IST is a 3 bit field, 32 bits into the IDT entry. */
    ASSERT(ist <= IST_MAX);

    idt->ist = ist;
}

static inline void enable_each_ist(idt_entry_t *idt)
{
    set_ist(&idt[X86_EXC_DF],  IST_DF);
    set_ist(&idt[X86_EXC_NMI], IST_NMI);
    set_ist(&idt[X86_EXC_MC],  IST_MCE);
    set_ist(&idt[X86_EXC_DB],  IST_DB);
}

static inline void disable_each_ist(idt_entry_t *idt)
{
    set_ist(&idt[X86_EXC_DF],  IST_NONE);
    set_ist(&idt[X86_EXC_NMI], IST_NONE);
    set_ist(&idt[X86_EXC_MC],  IST_NONE);
    set_ist(&idt[X86_EXC_DB],  IST_NONE);
}

#define _set_gate(gate_addr,type,dpl,addr)               \
do {                                                     \
    (gate_addr)->a = 0;                                  \
    smp_wmb(); /* disable gate /then/ rewrite */         \
    (gate_addr)->b =                                     \
        ((unsigned long)(addr) >> 32);                   \
    smp_wmb(); /* rewrite /then/ enable gate */          \
    (gate_addr)->a =                                     \
        (((unsigned long)(addr) & 0xFFFF0000UL) << 32) | \
        ((unsigned long)(dpl) << 45) |                   \
        ((unsigned long)(type) << 40) |                  \
        ((unsigned long)(addr) & 0xFFFFUL) |             \
        ((unsigned long)__HYPERVISOR_CS << 16) |         \
        (1UL << 47);                                     \
} while (0)

/*
 * Write the lower 64 bits of an IDT Entry. This relies on the upper 32
 * bits of the address not changing, which is a safe assumption as all
 * functions we are likely to load will live inside the 1GB
 * code/data/bss address range.
 */
static inline void _write_gate_lower(volatile idt_entry_t *gate,
                                     const idt_entry_t *new)
{
    ASSERT(gate->b == new->b);
    gate->a = new->a;
}

static inline void _set_gate_lower(idt_entry_t *gate, unsigned long type,
                                   unsigned long dpl, void *addr)
{
    idt_entry_t idte;
    idte.b = gate->b;
    idte.a =
        (((unsigned long)(addr) & 0xFFFF0000UL) << 32) |
        ((unsigned long)(dpl) << 45) |
        ((unsigned long)(type) << 40) |
        ((unsigned long)(addr) & 0xFFFFUL) |
        ((unsigned long)__HYPERVISOR_CS << 16) |
        (1UL << 47);
    _write_gate_lower(gate, &idte);
}

/*
 * Update the lower half handler of an IDT entry, without changing any other
 * configuration.
 */
static inline void _update_gate_addr_lower(idt_entry_t *gate, void *addr)
{
    idt_entry_t idte;
    idte.a = gate->a;

    idte.b = ((unsigned long)(addr) >> 32);
    idte.a &= 0x0000FFFFFFFF0000ULL;
    idte.a |= (((unsigned long)(addr) & 0xFFFF0000UL) << 32) |
        ((unsigned long)(addr) & 0xFFFFUL);

    _write_gate_lower(gate, &idte);
}

#endif /* X86_ASM_IDT_H */
