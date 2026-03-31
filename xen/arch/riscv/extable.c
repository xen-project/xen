/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/init.h>
#include <xen/bsearch.h>
#include <xen/lib.h>
#include <xen/livepatch.h>
#include <xen/sort.h>
#include <xen/virtual_region.h>

#include <asm/extable.h>
#include <asm/processor.h>

#define EX_FIELD(ptr, field) ((unsigned long)&(ptr)->field + (ptr)->field)

static inline unsigned long ex_insn(const struct exception_table_entry *ex)
{
    return EX_FIELD(ex, insn);
}

static inline unsigned long ex_fixup(const struct exception_table_entry *ex)
{
    return EX_FIELD(ex, fixup);
}

static void __init cf_check swap_ex(void *a, void *b)
{
    struct exception_table_entry *x = a, *y = b, tmp;
    long delta = b - a;

    tmp = *x;
    x->insn = y->insn + delta;
    y->insn = tmp.insn - delta;

    x->fixup = y->fixup + delta;
    y->fixup = tmp.fixup - delta;
}

static int cf_check cmp_ex(const void *a, const void *b)
{
    const unsigned long insn_a = ex_insn(a);
    const unsigned long insn_b = ex_insn(b);

    return (insn_a > insn_b) - (insn_a < insn_b);
}

void init_or_livepatch sort_exception_table(struct exception_table_entry *start,
                                 const struct exception_table_entry *stop)
{
    sort(start, stop - start, sizeof(*start), cmp_ex, swap_ex);
}

void __init sort_exception_tables(void)
{
    sort_exception_table(__start___ex_table, __stop___ex_table);
}

static void ex_handler_fixup(const struct exception_table_entry *ex,
                             struct cpu_user_regs *regs)
{
    regs->sepc = ex_fixup(ex);
}

bool fixup_exception(struct cpu_user_regs *regs)
{
    unsigned long pc = regs->sepc;
    const struct virtual_region *region = find_text_region(pc);
    const struct exception_table_entry *ex;
    struct exception_table_entry key;

    if ( !region || !region->ex )
        return false;

    key.insn = pc - (unsigned long)&key.insn;

    ex = bsearch(&key, region->ex, region->ex_end - region->ex, sizeof(key),
                 cmp_ex);

    if ( !ex )
        return false;

    ex_handler_fixup(ex, regs);

    return true;
}
