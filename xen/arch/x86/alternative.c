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

#include <xen/delay.h>
#include <xen/types.h>
#include <asm/apic.h>
#include <asm/processor.h>
#include <asm/alternative.h>
#include <xen/init.h>
#include <asm/setup.h>
#include <asm/system.h>
#include <asm/traps.h>
#include <asm/nmi.h>
#include <asm/nops.h>
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
    K8_NOP8,
    K8_NOP9,
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
    k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
    k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
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
    P6_NOP8,
    P6_NOP9,
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
    p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
    p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

static const unsigned char * const *ideal_nops init_or_livepatch_data = p6_nops;

#ifdef HAVE_AS_NOPS_DIRECTIVE

/* Nops in .init.rodata to compare against the runtime ideal nops. */
asm ( ".pushsection .init.rodata, \"a\", @progbits\n\t"
      "toolchain_nops: .nops " __stringify(ASM_NOP_MAX) "\n\t"
      ".popsection\n\t");
extern char toolchain_nops[ASM_NOP_MAX];
static bool init_or_livepatch_read_mostly toolchain_nops_are_ideal;

#else
# define toolchain_nops_are_ideal false
#endif

static void __init arch_init_ideal_nops(void)
{
    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        /*
         * Due to a decoder implementation quirk, some specific Intel CPUs
         * actually perform better with the "k8_nops" than with the SDM-
         * recommended NOPs.
         */
        if ( boot_cpu_data.x86 != 6 )
            break;

        switch ( boot_cpu_data.x86_model )
        {
        case 0x0f ... 0x1b:
        case 0x1d ... 0x25:
        case 0x28 ... 0x2f:
            ideal_nops = k8_nops;
            break;
        }
        break;

    case X86_VENDOR_AMD:
        if ( boot_cpu_data.x86 <= 0xf )
            ideal_nops = k8_nops;
        break;
    }

#ifdef HAVE_AS_NOPS_DIRECTIVE
    if ( memcmp(ideal_nops[ASM_NOP_MAX], toolchain_nops, ASM_NOP_MAX) == 0 )
        toolchain_nops_are_ideal = true;
#endif
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
 *
 * The caller will set the "force" argument to true for the final
 * invocation, such that no CALLs/JMPs to NULL pointers will be left
 * around. See also the further comment below.
 */
static void init_or_livepatch _apply_alternatives(struct alt_instr *start,
                                                  struct alt_instr *end,
                                                  bool force)
{
    struct alt_instr *a, *base;

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
    for ( a = base = start; a < end; a++ )
    {
        uint8_t *orig = ALT_ORIG_PTR(a);
        uint8_t *repl = ALT_REPL_PTR(a);
        uint8_t buf[MAX_PATCH_LEN];
        unsigned int total_len = a->orig_len + a->pad_len;

        BUG_ON(a->repl_len > total_len);
        BUG_ON(total_len > sizeof(buf));
        BUG_ON(a->cpuid >= NCAPINTS * 32);

        /*
         * Detect sequences of alt_instr's patching the same origin site, and
         * keep base pointing at the first alt_instr entry.  This is so we can
         * refer to a single ->priv field for some of our patching decisions,
         * in particular the NOP optimization. We deliberately use the alt_instr
         * itself rather than a local variable in case we end up making multiple
         * passes.
         *
         * ->priv being nonzero means that the origin site has already been
         * modified, and we shouldn't try to optimise the nops again.
         */
        if ( ALT_ORIG_PTR(base) != orig )
            base = a;

        /* Skip patch sites already handled during the first pass. */
        if ( a->priv )
        {
            ASSERT(force);
            continue;
        }

        /* If there is no replacement to make, see about optimising the nops. */
        if ( !boot_cpu_has(a->cpuid) )
        {
            /* Origin site site already touched?  Don't nop anything. */
            if ( base->priv )
                continue;

            a->priv = 1;

            /* Nothing useful to do? */
            if ( toolchain_nops_are_ideal || a->pad_len <= 1 )
                continue;

            add_nops(buf, a->pad_len);
            text_poke(orig + a->orig_len, buf, a->pad_len);
            continue;
        }

        memcpy(buf, repl, a->repl_len);

        /* 0xe8/0xe9 are relative branches; fix the offset. */
        if ( a->repl_len >= 5 && (*buf & 0xfe) == 0xe8 )
        {
            /*
             * Detect the special case of indirect-to-direct branch patching:
             * - replacement is a direct CALL/JMP (opcodes 0xE8/0xE9; already
             *   checked above),
             * - replacement's displacement is -5 (pointing back at the very
             *   insn, which makes no sense in a real replacement insn),
             * - original is an indirect CALL/JMP (opcodes 0xFF/2 or 0xFF/4)
             *   using RIP-relative addressing.
             * Some branch destinations may still be NULL when we come here
             * the first time. Defer patching of those until the post-presmp-
             * initcalls re-invocation (with force set to true). If at that
             * point the branch destination is still NULL, insert "UD2; UD0"
             * (for ease of recognition) instead of CALL/JMP.
             */
            if ( a->cpuid == X86_FEATURE_ALWAYS &&
                 *(int32_t *)(buf + 1) == -5 &&
                 a->orig_len >= 6 &&
                 orig[0] == 0xff &&
                 orig[1] == (*buf & 1 ? 0x25 : 0x15) )
            {
                long disp = *(int32_t *)(orig + 2);
                const uint8_t *dest = *(void **)(orig + 6 + disp);

                if ( dest )
                {
                    disp = dest - (orig + 5);
                    ASSERT(disp == (int32_t)disp);
                    *(int32_t *)(buf + 1) = disp;
                }
                else if ( force )
                {
                    buf[0] = 0x0f;
                    buf[1] = 0x0b;
                    buf[2] = 0x0f;
                    buf[3] = 0xff;
                    buf[4] = 0xff;
                }
                else
                    continue;
            }
            else if ( force && system_state < SYS_STATE_active )
                ASSERT_UNREACHABLE();
            else
                *(int32_t *)(buf + 1) += repl - orig;
        }
        else if ( force && system_state < SYS_STATE_active  )
            ASSERT_UNREACHABLE();

        a->priv = 1;

        add_nops(buf + a->repl_len, total_len - a->repl_len);
        text_poke(orig, buf, total_len);
    }
}

void init_or_livepatch apply_alternatives(struct alt_instr *start,
                                          struct alt_instr *end)
{
    _apply_alternatives(start, end, true);
}

static unsigned int __initdata alt_todo;
static unsigned int __initdata alt_done;

/*
 * At boot time, we patch alternatives in NMI context.  This means that the
 * active NMI-shadow will defer any further NMIs, removing the slim race
 * condition where an NMI hits while we are midway though patching some
 * instructions in the NMI path.
 */
static int __init nmi_apply_alternatives(const struct cpu_user_regs *regs,
                                         int cpu)
{
    /*
     * More than one NMI may occur between the two set_nmi_callback() below.
     * We only need to apply alternatives once.
     */
    if ( !(alt_done & alt_todo) )
    {
        unsigned long cr0;

        cr0 = read_cr0();

        /* Disable WP to allow patching read-only pages. */
        write_cr0(cr0 & ~X86_CR0_WP);

        _apply_alternatives(__alt_instructions, __alt_instructions_end,
                            alt_done);

        write_cr0(cr0);

        alt_done |= alt_todo;
    }

    return 1;
}

/*
 * This routine is called with local interrupt disabled and used during
 * bootup.
 */
static void __init _alternative_instructions(bool force)
{
    unsigned int i;
    nmi_callback_t *saved_nmi_callback;

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

    /* Set what operation to perform /before/ setting the callback. */
    alt_todo = 1u << force;
    barrier();

    /*
     * As soon as the callback is set up, the next NMI will trigger patching,
     * even an NMI ahead of our explicit self-NMI.
     */
    saved_nmi_callback = set_nmi_callback(nmi_apply_alternatives);

    /* Send ourselves an NMI to trigger the callback. */
    self_nmi();

    /*
     * In practice, the self_nmi() above appears to act synchronously.
     * However, synchronous behaviour is not architecturally guaranteed.  To
     * cover the (hopefully never) async case, poll alt_done for up to one
     * second.
     */
    for ( i = 0; !(ACCESS_ONCE(alt_done) & alt_todo) && i < 1000; ++i )
        mdelay(1);

    if ( !(ACCESS_ONCE(alt_done) & alt_todo) )
        panic("Timed out waiting for alternatives self-NMI to hit\n");

    set_nmi_callback(saved_nmi_callback);

    /*
     * When Xen is using shadow stacks, the alternatives clearing CR0.WP and
     * writing into the mappings set dirty bits, turning the mappings into
     * shadow stack mappings.
     *
     * While we can execute from them, this would also permit them to be the
     * target of WRSS instructions, so reset the dirty after patching.
     */
    if ( cpu_has_xen_shstk )
        modify_xen_mappings(XEN_VIRT_START + MB(2),
                            (unsigned long)&__2M_text_end,
                            PAGE_HYPERVISOR_RX);
}

void __init alternative_instructions(void)
{
    arch_init_ideal_nops();
    _alternative_instructions(false);
}

void __init alternative_branches(void)
{
    local_irq_disable();
    _alternative_instructions(true);
    local_irq_enable();
}
