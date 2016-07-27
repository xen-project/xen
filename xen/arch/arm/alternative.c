/*
 * alternative runtime patching
 * inspired by the x86 version
 *
 * Copyright (C) 2014-2016 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/smp.h>
#include <xen/stop_machine.h>
#include <asm/alternative.h>
#include <asm/atomic.h>
#include <asm/byteorder.h>
#include <asm/cpufeature.h>
#include <asm/insn.h>
#include <asm/page.h>

#define __ALT_PTR(a,f)      (u32 *)((void *)&(a)->f + (a)->f)
#define ALT_ORIG_PTR(a)     __ALT_PTR(a, orig_offset)
#define ALT_REPL_PTR(a)     __ALT_PTR(a, alt_offset)

extern const struct alt_instr __alt_instructions[], __alt_instructions_end[];

struct alt_region {
    const struct alt_instr *begin;
    const struct alt_instr *end;
};

/*
 * Check if the target PC is within an alternative block.
 */
static bool_t branch_insn_requires_update(const struct alt_instr *alt,
                                          unsigned long pc)
{
    unsigned long replptr;

    if ( is_active_kernel_text(pc) )
        return 1;

    replptr = (unsigned long)ALT_REPL_PTR(alt);
    if ( pc >= replptr && pc <= (replptr + alt->alt_len) )
        return 0;

    /*
     * Branching into *another* alternate sequence is doomed, and
     * we're not even trying to fix it up.
     */
    BUG();
}

static u32 get_alt_insn(const struct alt_instr *alt,
                        const u32 *insnptr, const u32 *altinsnptr)
{
    u32 insn;

    insn = le32_to_cpu(*altinsnptr);

    if ( insn_is_branch_imm(insn) )
    {
        s32 offset = insn_get_branch_offset(insn);
        unsigned long target;

        target = (unsigned long)altinsnptr + offset;

        /*
         * If we're branching inside the alternate sequence,
         * do not rewrite the instruction, as it is already
         * correct. Otherwise, generate the new instruction.
         */
        if ( branch_insn_requires_update(alt, target) )
        {
            offset = target - (unsigned long)insnptr;
            insn = insn_set_branch_offset(insn, offset);
        }
    }

    return insn;
}

static int __apply_alternatives(const struct alt_region *region)
{
    const struct alt_instr *alt;
    const u32 *origptr, *replptr;
    u32 *writeptr, *writemap;
    mfn_t text_mfn = _mfn(virt_to_mfn(_stext));
    unsigned int text_order = get_order_from_bytes(_end - _start);

    printk(XENLOG_INFO "alternatives: Patching kernel code\n");

    /*
     * The text section is read-only. So re-map Xen to be able to patch
     * the code.
     */
    writemap = __vmap(&text_mfn, 1 << text_order, 1, 1, PAGE_HYPERVISOR,
                      VMAP_DEFAULT);
    if ( !writemap )
    {
        printk(XENLOG_ERR "alternatives: Unable to map the text section (size %u)\n",
               1 << text_order);
        return -ENOMEM;
    }

    for ( alt = region->begin; alt < region->end; alt++ )
    {
        u32 insn;
        int i, nr_inst;

        if ( !cpus_have_cap(alt->cpufeature) )
            continue;

        BUG_ON(alt->alt_len != alt->orig_len);

        origptr = ALT_ORIG_PTR(alt);
        writeptr = origptr - (u32 *)_start + writemap;
        replptr = ALT_REPL_PTR(alt);

        nr_inst = alt->alt_len / sizeof(insn);

        for ( i = 0; i < nr_inst; i++ )
        {
            insn = get_alt_insn(alt, origptr + i, replptr + i);
            *(writeptr + i) = cpu_to_le32(insn);
        }

        /* Ensure the new instructions reached the memory and nuke */
        clean_and_invalidate_dcache_va_range(writeptr,
                                             (sizeof (*writeptr) * nr_inst));
    }

    /* Nuke the instruction cache */
    invalidate_icache();

    vunmap(writemap);

    return 0;
}

/*
 * We might be patching the stop_machine state machine, so implement a
 * really simple polling protocol here.
 */
static int __apply_alternatives_multi_stop(void *unused)
{
    static int patched = 0;
    const struct alt_region region = {
        .begin = __alt_instructions,
        .end = __alt_instructions_end,
    };

    /* We always have a CPU 0 at this point (__init) */
    if ( smp_processor_id() )
    {
        while ( !read_atomic(&patched) )
            cpu_relax();
        isb();
    }
    else
    {
        int ret;

        BUG_ON(patched);
        ret = __apply_alternatives(&region);
        /* The patching is not expected to fail during boot. */
        BUG_ON(ret != 0);

        /* Barriers provided by the cache flushing */
        write_atomic(&patched, 1);
    }

    return 0;
}

/*
 * This function should only be called during boot and before CPU0 jump
 * into the idle_loop.
 */
void __init apply_alternatives_all(void)
{
    int ret;

    ASSERT(system_state != SYS_STATE_active);

	/* better not try code patching on a live SMP system */
    ret = stop_machine_run(__apply_alternatives_multi_stop, NULL, NR_CPUS);

    /* stop_machine_run should never fail at this stage of the boot */
    BUG_ON(ret);
}

int apply_alternatives(void *start, size_t length)
{
    const struct alt_region region = {
        .begin = start,
        .end = start + length,
    };

    return __apply_alternatives(&region);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
