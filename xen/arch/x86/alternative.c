/******************************************************************************
 * alternative.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <asm/processor.h>
#include <asm/alternative.h>
#include <xen/init.h>
#include <asm/system.h>
#include <asm/traps.h>
#include <asm/nmi.h>
#include <xen/livepatch.h>

#define MAX_PATCH_LEN (255-1)

extern struct alt_instr __alt_instructions[], __alt_instructions_end[];

#ifdef K8_NOP1
static const unsigned char k8nops[] init_or_livepatch_const = {
    K8_NOP1,
    K8_NOP2,
    K8_NOP3,
    K8_NOP4,
    K8_NOP5,
    K8_NOP6,
    K8_NOP7,
    K8_NOP8
};
static const unsigned char * const k8_nops[ASM_NOP_MAX+1] init_or_livepatch_constrel = {
    NULL,
    k8nops,
    k8nops + 1,
    k8nops + 1 + 2,
    k8nops + 1 + 2 + 3,
    k8nops + 1 + 2 + 3 + 4,
    k8nops + 1 + 2 + 3 + 4 + 5,
    k8nops + 1 + 2 + 3 + 4 + 5 + 6,
    k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7
};
#endif

#ifdef P6_NOP1
static const unsigned char p6nops[] init_or_livepatch_const = {
    P6_NOP1,
    P6_NOP2,
    P6_NOP3,
    P6_NOP4,
    P6_NOP5,
    P6_NOP6,
    P6_NOP7,
    P6_NOP8
};
static const unsigned char * const p6_nops[ASM_NOP_MAX+1] init_or_livepatch_constrel = {
    NULL,
    p6nops,
    p6nops + 1,
    p6nops + 1 + 2,
    p6nops + 1 + 2 + 3,
    p6nops + 1 + 2 + 3 + 4,
    p6nops + 1 + 2 + 3 + 4 + 5,
    p6nops + 1 + 2 + 3 + 4 + 5 + 6,
    p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7
};
#endif

static const unsigned char * const *ideal_nops init_or_livepatch_data = k8_nops;

static int __init mask_nmi_callback(const struct cpu_user_regs *regs, int cpu)
{
    return 1;
}

static void __init arch_init_ideal_nops(void)
{
    /*
     * Due to a decoder implementation quirk, some
     * specific Intel CPUs actually perform better with
     * the "k8_nops" than with the SDM-recommended NOPs.
     */
    if ( (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) &&
         !(boot_cpu_data.x86 == 6 &&
           boot_cpu_data.x86_model >= 0x0f &&
           boot_cpu_data.x86_model != 0x1c &&
           boot_cpu_data.x86_model != 0x26 &&
           boot_cpu_data.x86_model != 0x27 &&
           boot_cpu_data.x86_model < 0x30) )
        ideal_nops = p6_nops;
}

/* Use this to add nops to a buffer, then text_poke the whole buffer. */
void init_or_livepatch add_nops(void *insns, unsigned int len)
{
    while ( len > 0 )
    {
        unsigned int noplen = len;
        if ( noplen > ASM_NOP_MAX )
            noplen = ASM_NOP_MAX;
        memcpy(insns, ideal_nops[noplen], noplen);
        insns += noplen;
        len -= noplen;
    }
}

/*
 * text_poke - Update instructions on a live kernel or non-executed code.
 * @addr: address to modify
 * @opcode: source of the copy
 * @len: length to copy
 *
 * When you use this code to patch more than one byte of an instruction
 * you need to make sure that other CPUs cannot execute this code in parallel.
 * Also no thread must be currently preempted in the middle of these
 * instructions. And on the local CPU you need to be protected again NMI or MCE
 * handlers seeing an inconsistent instruction while you patch.
 *
 * You should run this with interrupts disabled or on code that is not
 * executing.
 *
 * "noinline" to cause control flow change and thus invalidate I$ and
 * cause refetch after modification.
 */
static void *init_or_livepatch noinline
text_poke(void *addr, const void *opcode, size_t len)
{
    return memcpy(addr, opcode, len);
}

/*
 * Replace instructions with better alternatives for this CPU type.
 * This runs before SMP is initialized to avoid SMP problems with
 * self modifying code. This implies that asymmetric systems where
 * APs have less capabilities than the boot processor are not handled.
 * Tough. Make sure you disable such features by hand.
 */
void init_or_livepatch apply_alternatives(const struct alt_instr *start,
                                          const struct alt_instr *end)
{
    const struct alt_instr *a;
    u8 *instr, *replacement;
    u8 insnbuf[MAX_PATCH_LEN];

    printk(KERN_INFO "alt table %p -> %p\n", start, end);

    /*
     * The scan order should be from start to end. A later scanned
     * alternative code can overwrite a previous scanned alternative code.
     * Some kernel functions (e.g. memcpy, memset, etc) use this order to
     * patch code.
     *
     * So be careful if you want to change the scan order to any other
     * order.
     */
    for ( a = start; a < end; a++ )
    {
        instr = (u8 *)&a->instr_offset + a->instr_offset;
        replacement = (u8 *)&a->repl_offset + a->repl_offset;
        BUG_ON(a->replacementlen > a->instrlen);
        BUG_ON(a->instrlen > sizeof(insnbuf));
        BUG_ON(a->cpuid >= NCAPINTS * 32);
        if ( !boot_cpu_has(a->cpuid) )
            continue;

        memcpy(insnbuf, replacement, a->replacementlen);

        /* 0xe8/0xe9 are relative branches; fix the offset. */
        if ( a->replacementlen >= 5 && (*insnbuf & 0xfe) == 0xe8 )
            *(s32 *)(insnbuf + 1) += replacement - instr;

        add_nops(insnbuf + a->replacementlen,
                 a->instrlen - a->replacementlen);
        text_poke(instr, insnbuf, a->instrlen);
    }
}

/*
 * This routine is called with local interrupt disabled and used during
 * bootup.
 */
void __init alternative_instructions(void)
{
    nmi_callback_t *saved_nmi_callback;
    unsigned long cr0 = read_cr0();

    arch_init_ideal_nops();

    /*
     * The patching is not fully atomic, so try to avoid local interruptions
     * that might execute the to be patched code.
     * Other CPUs are not running.
     */
    saved_nmi_callback = set_nmi_callback(mask_nmi_callback);

    /*
     * Don't stop machine check exceptions while patching.
     * MCEs only happen when something got corrupted and in this
     * case we must do something about the corruption.
     * Ignoring it is worse than a unlikely patching race.
     * Also machine checks tend to be broadcast and if one CPU
     * goes into machine check the others follow quickly, so we don't
     * expect a machine check to cause undue problems during to code
     * patching.
     */
    ASSERT(!local_irq_is_enabled());

    /* Disable WP to allow application of alternatives to read-only pages. */
    write_cr0(cr0 & ~X86_CR0_WP);

    apply_alternatives(__alt_instructions, __alt_instructions_end);

    /* Reinstate WP. */
    write_cr0(cr0);

    set_nmi_callback(saved_nmi_callback);
}
