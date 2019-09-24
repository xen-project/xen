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

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/vmap.h>
#include <xen/smp.h>
#include <xen/stop_machine.h>
#include <xen/virtual_region.h>
#include <asm/alternative.h>
#include <asm/atomic.h>
#include <asm/byteorder.h>
#include <asm/cpufeature.h>
#include <asm/insn.h>
#include <asm/page.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

extern const struct alt_instr __alt_instructions[], __alt_instructions_end[];

struct alt_region {
    const struct alt_instr *begin;
    const struct alt_instr *end;
};

/*
 * Check if the target PC is within an alternative block.
 */
static bool branch_insn_requires_update(const struct alt_instr *alt,
                                        unsigned long pc)
{
    unsigned long replptr;

    if ( is_active_kernel_text(pc) )
        return true;

    replptr = (unsigned long)ALT_REPL_PTR(alt);
    if ( pc >= replptr && pc <= (replptr + alt->alt_len) )
        return false;

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

static void patch_alternative(const struct alt_instr *alt,
                              const uint32_t *origptr,
                              uint32_t *updptr, int nr_inst)
{
    const uint32_t *replptr;
    unsigned int i;

    replptr = ALT_REPL_PTR(alt);
    for ( i = 0; i < nr_inst; i++ )
    {
        uint32_t insn;

        insn = get_alt_insn(alt, origptr + i, replptr + i);
        updptr[i] = cpu_to_le32(insn);
    }
}

/*
 * The region patched should be read-write to allow __apply_alternatives
 * to replacing the instructions when necessary.
 *
 * @update_offset: Offset between the region patched and the writable
 * region for the update. 0 if the patched region is writable.
 */
static int __apply_alternatives(const struct alt_region *region,
                                paddr_t update_offset)
{
    const struct alt_instr *alt;
    const u32 *origptr;
    u32 *updptr;
    alternative_cb_t alt_cb;

    printk(XENLOG_INFO "alternatives: Patching with alt table %p -> %p\n",
           region->begin, region->end);

    for ( alt = region->begin; alt < region->end; alt++ )
    {
        int nr_inst;

        /* Use ARM_CB_PATCH as an unconditional patch */
        if ( alt->cpufeature < ARM_CB_PATCH &&
             !cpus_have_cap(alt->cpufeature) )
            continue;

        if ( alt->cpufeature == ARM_CB_PATCH )
            BUG_ON(alt->alt_len != 0);
        else
            BUG_ON(alt->alt_len != alt->orig_len);

        origptr = ALT_ORIG_PTR(alt);
        updptr = (void *)origptr + update_offset;

        nr_inst = alt->orig_len / ARCH_PATCH_INSN_SIZE;

        if ( alt->cpufeature < ARM_CB_PATCH )
            alt_cb = patch_alternative;
        else
            alt_cb = ALT_REPL_PTR(alt);

        alt_cb(alt, origptr, updptr, nr_inst);

        /* Ensure the new instructions reached the memory and nuke */
        clean_and_invalidate_dcache_va_range(origptr,
                                             (sizeof (*origptr) * nr_inst));
    }

    /* Nuke the instruction cache */
    invalidate_icache();

    return 0;
}

/*
 * We might be patching the stop_machine state machine, so implement a
 * really simple polling protocol here.
 */
static int __apply_alternatives_multi_stop(void *unused)
{
    static int patched = 0;

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
        struct alt_region region;
        mfn_t xen_mfn = virt_to_mfn(_start);
        paddr_t xen_size = _end - _start;
        unsigned int xen_order = get_order_from_bytes(xen_size);
        void *xenmap;

        BUG_ON(patched);

        /*
         * The text and inittext section are read-only. So re-map Xen to
         * be able to patch the code.
         */
        xenmap = __vmap(&xen_mfn, 1U << xen_order, 1, 1, PAGE_HYPERVISOR,
                        VMAP_DEFAULT);
        /* Re-mapping Xen is not expected to fail during boot. */
        BUG_ON(!xenmap);

        region.begin = __alt_instructions;
        region.end = __alt_instructions_end;

        ret = __apply_alternatives(&region, xenmap - (void *)_start);
        /* The patching is not expected to fail during boot. */
        BUG_ON(ret != 0);

        vunmap(xenmap);

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

int apply_alternatives(const struct alt_instr *start, const struct alt_instr *end)
{
    const struct alt_region region = {
        .begin = start,
        .end = end,
    };

    return __apply_alternatives(&region, 0);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
