/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * alternative.c
 */

#include <xen/delay.h>
#include <xen/types.h>
#include <asm/apic.h>
#include <asm/endbr.h>
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

void nocall __x86_return_thunk(void);

/*
 * Place a return at @ptr.  @ptr must be in the writable alias of a stub.
 *
 * When CONFIG_RETURN_THUNK is active, this may be a JMP __x86_return_thunk
 * instead, depending on the safety of @ptr with respect to Indirect Target
 * Selection.
 *
 * Returns the next position to write into the stub.
 */
void *place_ret(void *ptr)
{
    unsigned long addr = (unsigned long)ptr;
    uint8_t *p = ptr;

    /*
     * When Return Thunks are used, if a RET would be unsafe at this location
     * with respect to Indirect Target Selection (i.e. if addr is in the first
     * half of a cacheline), insert a JMP __x86_return_thunk instead.
     *
     * The displacement needs to be relative to the executable alias of the
     * stub, not to @ptr which is the writeable alias.
     */
    if ( IS_ENABLED(CONFIG_RETURN_THUNK) && !(addr & 0x20) )
    {
        long stub_va = (this_cpu(stubs.addr) & PAGE_MASK) + (addr & ~PAGE_MASK);
        long disp = (long)__x86_return_thunk - (stub_va + 5);

        BUG_ON((int32_t)disp != disp);

        *p++ = 0xe9;
        *(int32_t *)p = disp;
        p += 4;
    }
    else
    {
        *p++ = 0xc3;
    }

    return p;
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
static void init_or_livepatch noinline
text_poke(void *addr, const void *opcode, size_t len)
{
    memcpy(addr, opcode, len);
}

extern void *const __initdata_cf_clobber_start[];
extern void *const __initdata_cf_clobber_end[];

/*
 * In CET-IBT enabled builds, clobber endbr64 instructions after altcall has
 * finished optimising all indirect branches to direct ones.
 */
static void __init seal_endbr64(void)
{
    void *const *val;
    unsigned int clobbered = 0;

    if ( !cpu_has_xen_ibt )
        return;

    /*
     * This is some minor structure (ab)use.  We walk the entire contents
     * of .init.{ro,}data.cf_clobber as if it were an array of pointers.
     *
     * If the pointer points into .text, and at an endbr64 instruction,
     * nop out the endbr64.  This causes the pointer to no longer be a
     * legal indirect branch target under CET-IBT.  This is a
     * defence-in-depth measure, to reduce the options available to an
     * adversary who has managed to hijack a function pointer.
     */
    for ( val = __initdata_cf_clobber_start;
          val < __initdata_cf_clobber_end;
          val++ )
    {
        void *ptr = *val;

        if ( !is_kernel_text(ptr) || !is_endbr64(ptr) )
            continue;

        place_endbr64_poison(ptr);
        clobbered++;
    }

    printk("altcall: Optimised away %u endbr64 instructions\n", clobbered);
}

/*
 * Replace instructions with better alternatives for this CPU type.
 * This runs before SMP is initialized to avoid SMP problems with
 * self modifying code. This implies that asymmetric systems where
 * APs have less capabilities than the boot processor are not handled.
 * Tough. Make sure you disable such features by hand.
 */
static int init_or_livepatch _apply_alternatives(struct alt_instr *start,
                                                 struct alt_instr *end)
{
    struct alt_instr *a, *base;

    printk(KERN_INFO "alt table %p -> %p\n", start, end);

    /*
     * The scan order should be from start to end. A later scanned
     * alternative code can overwrite a previous scanned alternative code.
     * Some code (e.g. ALTERNATIVE_2()) relies on this order of patching.
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
        unsigned int feat = a->cpuid & ~ALT_FLAG_NOT;
        bool inv = a->cpuid & ALT_FLAG_NOT, replace;

        if ( a->repl_len > total_len )
        {
            printk(XENLOG_ERR
                   "Alt for %ps, replacement size %#x larger than origin %#x\n",
                    ALT_ORIG_PTR(a), a->repl_len, total_len);
            return -ENOSPC;
        }

        if ( total_len > sizeof(buf) )
        {
            printk(XENLOG_ERR
                   "Alt for %ps, origin size %#x bigger than buffer %#zx\n",
                   ALT_ORIG_PTR(a), total_len, sizeof(buf));
            return -ENOSPC;
        }

        if ( feat >= NCAPINTS * 32 )
        {
             printk(XENLOG_ERR
                   "Alt for %ps, feature %#x outside of featureset range %#x\n",
                   ALT_ORIG_PTR(a), feat, NCAPINTS * 32);
            return -ERANGE;
        }

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
            continue;

        /*
         * Should a replacement be performed?  Most replacements have positive
         * polarity, but we support negative polarity too.
         */
        replace = boot_cpu_has(feat) ^ inv;

        /* If there is no replacement to make, see about optimising the nops. */
        if ( !replace )
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
            *(int32_t *)(buf + 1) += repl - orig;

        a->priv = 1;

        add_nops(buf + a->repl_len, total_len - a->repl_len);
        text_poke(orig, buf, total_len);
    }

    return 0;
}

/*
 * At build time, alternative calls are emitted as:
 *   ff 15 xx xx xx xx  =>  call *disp32(%rip)
 *
 * During boot, we devirtualise by editing to:
 *   2e e8 xx xx xx xx  =>  cs call disp32
 *
 * or, if the function pointer is still NULL, poison to:
 *   0f 0b 0f 0b 0f 0b  =>  ud2a (x3)
 */
static int init_or_livepatch apply_alt_calls(
    const struct alt_call *start, const struct alt_call *end)
{
    const struct alt_call *a;

    for ( a = start; a < end; a++ )
    {
        const uint8_t *dest;
        uint8_t buf[6], *orig = ALT_CALL_PTR(a);
        long disp;

        /* It's likely that this won't change, but check just to be safe. */
        BUILD_BUG_ON(ALT_CALL_LEN(a) != 6);

        if ( orig[0] != 0xff || orig[1] != 0x15 )
        {
            printk(XENLOG_ERR
                   "Altcall for %ps [%6ph] not CALL *RIPREL\n",
                   orig, orig);
            return -EINVAL;
        }

        disp = *(int32_t *)(orig + 2);
        dest = *(const void **)(orig + 6 + disp);

        if ( dest )
        {
            /*
             * When building for CET-IBT, all function pointer targets
             * should have an endbr64 instruction.
             *
             * If this is not the case, leave a warning because
             * something is probably wrong with the build.  A CET-IBT
             * enabled system might have exploded already.
             *
             * Otherwise, skip the endbr64 instruction.  This is a
             * marginal perf improvement which saves on instruction
             * decode bandwidth.
             */
            if ( IS_ENABLED(CONFIG_XEN_IBT) )
            {
                if ( is_endbr64(dest) )
                    dest += ENDBR64_LEN;
                else
                    printk(XENLOG_WARNING
                           "Altcall %ps dest %ps has no endbr64\n",
                           orig, dest);
            }

            disp = dest - (orig + 6);
            ASSERT(disp == (int32_t)disp);

            buf[0] = 0x2e;
            buf[1] = 0xe8;
            *(int32_t *)(buf + 2) = disp;
        }
        else
        {
            /*
             * The function pointer is still NULL.  Seal the whole call, as
             * it's not used.
             */
            buf[0] = 0x0f;
            buf[1] = 0x0b;
            buf[2] = 0x0f;
            buf[3] = 0x0b;
            buf[4] = 0x0f;
            buf[5] = 0x0b;
        }

        text_poke(orig, buf, sizeof(buf));
    }

    return 0;
}

#ifdef CONFIG_LIVEPATCH
int apply_alternatives(struct alt_instr *start, struct alt_instr *end)
{
    return _apply_alternatives(start, end);
}

int livepatch_apply_alt_calls(const struct alt_call *start,
                              const struct alt_call *end)
{
    return apply_alt_calls(start, end);
}
#endif

#define ALT_INSNS (1U << 0)
#define ALT_CALLS (1U << 1)
static unsigned int __initdata alt_todo;
static unsigned int __initdata alt_done;

extern struct alt_instr __alt_instructions[], __alt_instructions_end[];
extern struct alt_call __alt_call_sites_start[], __alt_call_sites_end[];

/*
 * At boot time, we patch alternatives in NMI context.  This means that the
 * active NMI-shadow will defer any further NMIs, removing the slim race
 * condition where an NMI hits while we are midway though patching some
 * instructions in the NMI path.
 */
static int __init cf_check nmi_apply_alternatives(
    const struct cpu_user_regs *regs, int cpu)
{
    /*
     * More than one NMI may occur between the two set_nmi_callback() below.
     * We only need to apply alternatives once.
     */
    if ( !(alt_done & alt_todo) )
    {
        int rc;

        /*
         * Relax perms on .text to be RWX, so we can modify them.
         *
         * This relaxes perms globally, but we run ahead of bringing APs
         * online, so only have our own TLB to worry about.
         */
        modify_xen_mappings_lite(XEN_VIRT_START + MB(2),
                                 (unsigned long)&__2M_text_end,
                                 PAGE_HYPERVISOR_RWX);
        flush_local(FLUSH_TLB_GLOBAL);

        if ( alt_todo & ALT_INSNS )
        {
            rc = _apply_alternatives(__alt_instructions,
                                     __alt_instructions_end);
            if ( rc )
                panic("Unable to apply alternatives: %d\n", rc);
        }

        if ( alt_todo & ALT_CALLS )
        {
            rc = apply_alt_calls(__alt_call_sites_start, __alt_call_sites_end);
            if ( rc )
                panic("Unable to apply alternative calls: %d\n", rc);

            seal_endbr64();
        }

        /*
         * Reinstate perms on .text to be RX.  This also cleans out the dirty
         * bits, which matters when CET Shstk is active.
         */
        modify_xen_mappings_lite(XEN_VIRT_START + MB(2),
                                 (unsigned long)&__2M_text_end,
                                 PAGE_HYPERVISOR_RX);
        flush_local(FLUSH_TLB_GLOBAL);

        alt_done |= alt_todo;
    }

    return 1;
}

/*
 * This routine is called with local interrupt disabled and used during
 * bootup.
 */
static void __init _alternative_instructions(unsigned int what)
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
    alt_todo = what;
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
}

void __init alternative_instructions(void)
{
    arch_init_ideal_nops();
    _alternative_instructions(ALT_INSNS);
}

void __init boot_apply_alt_calls(void)
{
    local_irq_disable();
    _alternative_instructions(ALT_CALLS);
    local_irq_enable();
}
