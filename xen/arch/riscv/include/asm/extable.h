/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM__RISCV__ASM_EXTABLE_H
#define ASM__RISCV__ASM_EXTABLE_H

#ifdef __ASSEMBLER__

#define ASM_EXTABLE(insn, fixup) \
    .pushsection .ex_table, "a"; \
    .balign     4;               \
    .word       (insn) - .;      \
    .word       (fixup) - .;     \
    .popsection

.macro asm_extable, insn, fixup
    ASM_EXTABLE(\insn, \fixup)
.endm

#else /* __ASSEMBLER__ */

#include <xen/stringify.h>
#include <xen/types.h>

struct cpu_user_regs;

#define ASM_EXTABLE(insn, fixup)      \
    ".pushsection .ex_table, \"a\"\n" \
    ".balign    4\n"                  \
    ".word      (" #insn " - .)\n"    \
    ".word      (" #fixup " - .)\n"   \
    ".popsection\n"

/*
 * The exception table consists of pairs of relative offsets: the first
 * is the relative offset to an instruction that is allowed to fault,
 * and the second is the relative offset at which the program should
 * continue. No general-purpose registers are modified by the exception
 * handling mechanism itself, so it is up to the fixup code to handle
 * any necessary state cleanup.
 *
 * The exception table and fixup code live out of line with the main
 * instruction path. This means when everything is well, we don't even
 * have to jump over them. Further, they do not intrude on our cache or
 * tlb entries.
 */
struct exception_table_entry {
    int32_t insn, fixup;
};

extern struct exception_table_entry __start___ex_table[];
extern struct exception_table_entry __stop___ex_table[];

void sort_exception_tables(void);
bool fixup_exception(struct cpu_user_regs *regs);

#endif /* __ASSEMBLY__ */

#endif /* ASM__RISCV__ASM_EXTABLE_H */
