/*
 * mce.c - x86 Machine Check Exception Reporting
 * (c) 2002 Alan Cox <alan@redhat.com>, Dave Jones <davej@codemonkey.org.uk>
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/kernel.h>
#include <xen/smp.h>
#include <xen/errno.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/cpumask.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h> /* for do_mca */
#include <xen/cpu.h>

#include <asm/processor.h>
#include <asm/setup.h>
#include <asm/system.h>
#include <asm/apic.h>
#include <asm/msr.h>
#include <asm/p2m.h>

#include "mce.h"
#include "barrier.h"
#include "mcaction.h"
#include "util.h"
#include "vmce.h"

bool __read_mostly opt_mce = true;
boolean_param("mce", opt_mce);
bool __read_mostly mce_broadcast;
bool is_mc_panic;
DEFINE_PER_CPU_READ_MOSTLY(unsigned int, nr_mce_banks);
unsigned int __read_mostly firstbank;
uint8_t __read_mostly cmci_apic_vector;

DEFINE_PER_CPU_READ_MOSTLY(struct mca_banks *, poll_bankmask);
DEFINE_PER_CPU_READ_MOSTLY(struct mca_banks *, no_cmci_banks);
DEFINE_PER_CPU_READ_MOSTLY(struct mca_banks *, mce_clear_banks);

static void intpose_init(void);
static void mcinfo_clear(struct mc_info *);
struct mca_banks *mca_allbanks;

#define SEG_PL(segsel)   ((segsel) & 0x3)
#define _MC_MSRINJ_F_REQ_HWCR_WREN (1 << 16)

#if 0
#define x86_mcerr(fmt, err, args...)                                    \
    ({                                                                  \
        int _err = (err);                                               \
        gdprintk(XENLOG_WARNING, "x86_mcerr: " fmt ", returning %d\n",  \
                 ## args, _err);                                        \
        _err;                                                           \
    })
#else
#define x86_mcerr(fmt, err, args...) (err)
#endif

int mce_verbosity;
static int __init mce_set_verbosity(const char *str)
{
    if ( strcmp("verbose", str) == 0 )
        mce_verbosity = MCE_VERBOSE;
    else
        return -EINVAL;

    return 0;
}
custom_param("mce_verbosity", mce_set_verbosity);

/* Handle unconfigured int18 (should never happen) */
static void unexpected_machine_check(const struct cpu_user_regs *regs)
{
    console_force_unlock();
    printk("Unexpected Machine Check Exception\n");
    fatal_trap(regs, 1);
}

static x86_mce_vector_t _machine_check_vector = unexpected_machine_check;

void x86_mce_vector_register(x86_mce_vector_t hdlr)
{
    _machine_check_vector = hdlr;
}

/* Call the installed machine check handler for this CPU setup. */

void do_machine_check(const struct cpu_user_regs *regs)
{
    _machine_check_vector(regs);
}

/*
 * Init machine check callback handler
 * It is used to collect additional information provided by newer
 * CPU families/models without the need to duplicate the whole handler.
 * This avoids having many handlers doing almost nearly the same and each
 * with its own tweaks ands bugs.
 */
static x86_mce_callback_t mc_callback_bank_extended = NULL;

void x86_mce_callback_register(x86_mce_callback_t cbfunc)
{
    mc_callback_bank_extended = cbfunc;
}

/*
 * Machine check recoverable judgement callback handler
 * It is used to judge whether an UC error is recoverable by software
 */
static mce_recoverable_t mc_recoverable_scan = NULL;

void mce_recoverable_register(mce_recoverable_t cbfunc)
{
    mc_recoverable_scan = cbfunc;
}

struct mca_banks *mcabanks_alloc(unsigned int nr_mce_banks)
{
    struct mca_banks *mb;

    mb = xmalloc(struct mca_banks);
    if ( !mb )
        return NULL;

    /*
     * For APs allocations get done by the BSP, i.e. when the bank count may
     * may not be known yet. A zero bank count is a clear indication of this.
     */
    if ( !nr_mce_banks )
        nr_mce_banks = MCG_CAP_COUNT;

    mb->bank_map = xzalloc_array(unsigned long,
                                 BITS_TO_LONGS(nr_mce_banks));
    if ( !mb->bank_map )
    {
        xfree(mb);
        return NULL;
    }

    mb->num = nr_mce_banks;

    return mb;
}

void mcabanks_free(struct mca_banks *banks)
{
    if ( banks == NULL )
        return;
    if ( banks->bank_map )
        xfree(banks->bank_map);
    xfree(banks);
}

static void mcabank_clear(int banknum)
{
    uint64_t status;

    status = mca_rdmsr(MSR_IA32_MCx_STATUS(banknum));

    if ( status & MCi_STATUS_ADDRV )
        mca_wrmsr(MSR_IA32_MCx_ADDR(banknum), 0x0ULL);
    if ( status & MCi_STATUS_MISCV )
        mca_wrmsr(MSR_IA32_MCx_MISC(banknum), 0x0ULL);

    mca_wrmsr(MSR_IA32_MCx_STATUS(banknum), 0x0ULL);
}

/*
 * Judging whether to Clear Machine Check error bank callback handler
 * According to Intel latest MCA OS Recovery Writer's Guide,
 * whether the error MCA bank needs to be cleared is decided by the mca_source
 * and MCi_status bit value.
 */
static mce_need_clearbank_t mc_need_clearbank_scan = NULL;

void mce_need_clearbank_register(mce_need_clearbank_t cbfunc)
{
    mc_need_clearbank_scan = cbfunc;
}

/*
 * mce_logout_lock should only be used in the trap handler,
 * while MCIP has not been cleared yet in the global status
 * register. Other use is not safe, since an MCE trap can
 * happen at any moment, which would cause lock recursion.
 */
static DEFINE_SPINLOCK(mce_logout_lock);

const struct mca_error_handler *__read_mostly mce_dhandlers;
const struct mca_error_handler *__read_mostly mce_uhandlers;
unsigned int __read_mostly mce_dhandler_num;
unsigned int __read_mostly mce_uhandler_num;

static void mca_init_bank(enum mca_source who, struct mc_info *mi, int bank)
{
    struct mcinfo_bank *mib;

    if ( !mi )
        return;

    mib = x86_mcinfo_reserve(mi, sizeof(*mib), MC_TYPE_BANK);
    if ( !mib )
    {
        mi->flags |= MCINFO_FLAGS_UNCOMPLETE;
        return;
    }

    mib->mc_status = mca_rdmsr(MSR_IA32_MCx_STATUS(bank));

    mib->mc_bank = bank;
    mib->mc_domid = DOMID_INVALID;

    if ( mib->mc_status & MCi_STATUS_MISCV )
        mib->mc_misc = mca_rdmsr(MSR_IA32_MCx_MISC(bank));

    if ( mib->mc_status & MCi_STATUS_ADDRV )
        mib->mc_addr = mca_rdmsr(MSR_IA32_MCx_ADDR(bank));

    if ( (mib->mc_status & MCi_STATUS_MISCV) &&
         (mib->mc_status & MCi_STATUS_ADDRV) &&
         (mc_check_addr(mib->mc_status, mib->mc_misc, MC_ADDR_PHYSICAL)) &&
         (who == MCA_POLLER || who == MCA_CMCI_HANDLER) &&
         (mfn_valid(_mfn(paddr_to_pfn(mib->mc_addr)))) )
    {
        struct domain *d;

        d = maddr_get_owner(mib->mc_addr);
        if ( d )
            mib->mc_domid = d->domain_id;
    }

    if ( who == MCA_CMCI_HANDLER )
    {
        mib->mc_ctrl2 = mca_rdmsr(MSR_IA32_MC0_CTL2 + bank);
        mib->mc_tsc = rdtsc();
    }
}

static int mca_init_global(uint32_t flags, struct mcinfo_global *mig)
{
    uint64_t status;
    int cpu_nr;
    const struct vcpu *curr = current;

    /* Set global information */
    status = mca_rdmsr(MSR_IA32_MCG_STATUS);
    mig->mc_gstatus = status;
    mig->mc_domid = DOMID_INVALID;
    mig->mc_vcpuid = XEN_MC_VCPUID_INVALID;
    mig->mc_flags = flags;
    cpu_nr = smp_processor_id();
    /* Retrieve detector information */
    x86_mc_get_cpu_info(cpu_nr, &mig->mc_socketid,
                        &mig->mc_coreid, &mig->mc_core_threadid,
                        &mig->mc_apicid, NULL, NULL, NULL);

    if ( curr != INVALID_VCPU )
    {
        mig->mc_domid = curr->domain->domain_id;
        mig->mc_vcpuid = curr->vcpu_id;
    }

    return 0;
}

/*
 * Utility function to perform MCA bank telemetry readout and to push that
 * telemetry towards an interested dom0 for logging and diagnosis.
 * The caller - #MC handler or MCA poll function - must arrange that we
 * do not migrate cpus.
 */

/* XXFM Could add overflow counting? */

/*
 *  Add out_param clear_bank for Machine Check Handler Caller.
 * For Intel latest CPU, whether to clear the error bank status needs to
 * be judged by the callback function defined above.
 */
mctelem_cookie_t
mcheck_mca_logout(enum mca_source who, struct mca_banks *bankmask,
                  struct mca_summary *sp, struct mca_banks *clear_bank)
{
    uint64_t gstatus, status;
    struct mcinfo_global *mig = NULL; /* on stack */
    mctelem_cookie_t mctc = NULL;
    bool uc = false, pcc = false, recover = true, need_clear = true;
    uint32_t mc_flags = 0;
    struct mc_info *mci = NULL;
    mctelem_class_t which = MC_URGENT; /* XXXgcc */
    int errcnt = 0;
    int i;

    gstatus = mca_rdmsr(MSR_IA32_MCG_STATUS);
    switch ( who )
    {
    case MCA_MCE_SCAN:
        mc_flags = MC_FLAG_MCE;
        which = MC_URGENT;
        break;

    case MCA_POLLER:
    case MCA_RESET:
        mc_flags = MC_FLAG_POLLED;
        which = MC_NONURGENT;
        break;

    case MCA_CMCI_HANDLER:
        mc_flags = MC_FLAG_CMCI;
        which = MC_NONURGENT;
        break;

    default:
        BUG();
    }

    /*
     * If no mc_recovery_scan callback handler registered,
     * this error is not recoverable
     */
    recover = mc_recoverable_scan ? 1 : 0;

    for ( i = 0; i < this_cpu(nr_mce_banks); i++ )
    {
        /* Skip bank if corresponding bit in bankmask is clear */
        if ( !mcabanks_test(i, bankmask) )
            continue;

        status = mca_rdmsr(MSR_IA32_MCx_STATUS(i));
        if ( !(status & MCi_STATUS_VAL) )
            continue; /* this bank has no valid telemetry */

        /*
         * For Intel Latest CPU CMCI/MCE Handler caller, we need to
         * decide whether to clear bank by MCi_STATUS bit value such as
         * OVER/UC/EN/PCC/S/AR
         */
        if ( mc_need_clearbank_scan )
            need_clear = mc_need_clearbank_scan(who, status);

        /*
         * If this is the first bank with valid MCA DATA, then
         * try to reserve an entry from the urgent/nonurgent queue
         * depending on whether we are called from an exception or
         * a poller;  this can fail (for example dom0 may not
         * yet have consumed past telemetry).
         */
        if ( errcnt++ == 0 )
        {
            mctc = mctelem_reserve(which);
            if ( mctc )
            {
                mci = mctelem_dataptr(mctc);
                mcinfo_clear(mci);
                mig = x86_mcinfo_reserve(mci, sizeof(*mig), MC_TYPE_GLOBAL);
                /* mc_info should at least hold up the global information */
                ASSERT(mig);
                mca_init_global(mc_flags, mig);
                /* A hook here to get global extended msrs */
                if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
                    intel_get_extended_msrs(mig, mci);
            }
        }

        /* flag for uncorrected errors */
        if ( !uc && ((status & MCi_STATUS_UC) != 0) )
            uc = true;

        /* flag processor context corrupt */
        if ( !pcc && ((status & MCi_STATUS_PCC) != 0) )
            pcc = true;

        if ( recover && uc )
            /* uc = true, recover = true, we need not panic. */
            recover = mc_recoverable_scan(status);

        mca_init_bank(who, mci, i);

        if ( mc_callback_bank_extended )
            mc_callback_bank_extended(mci, i, status);

        /* By default, need_clear = true */
        if ( who != MCA_MCE_SCAN && need_clear )
            /* Clear bank */
            mcabank_clear(i);
        else if ( who == MCA_MCE_SCAN && need_clear )
            mcabanks_set(i, clear_bank);
    }

    if ( mig && errcnt > 0 )
    {
        if ( pcc )
            mig->mc_flags |= MC_FLAG_UNCORRECTABLE;
        else if ( uc )
            mig->mc_flags |= MC_FLAG_RECOVERABLE;
        else
            mig->mc_flags |= MC_FLAG_CORRECTABLE;
    }

    if ( sp )
    {
        sp->errcnt = errcnt;
        sp->ripv = (gstatus & MCG_STATUS_RIPV) != 0;
        sp->eipv = (gstatus & MCG_STATUS_EIPV) != 0;
        sp->lmce = (gstatus & MCG_STATUS_LMCE) != 0;
        sp->uc = uc;
        sp->pcc = pcc;
        sp->recoverable = recover;
    }

    return mci != NULL ? mctc : NULL; /* may be NULL */
}

static void mce_spin_lock(spinlock_t *lk)
{
    while ( !spin_trylock(lk) )
    {
        cpu_relax();
        mce_panic_check();
    }
}

static void mce_spin_unlock(spinlock_t *lk)
{
    spin_unlock(lk);
}

static enum mce_result mce_action(const struct cpu_user_regs *regs,
                                  mctelem_cookie_t mctc);

/*
 * Return:
 * -1: if system can't be recovered
 * 0: Continue to next step
 */
static int mce_urgent_action(const struct cpu_user_regs *regs,
                             mctelem_cookie_t mctc)
{
    uint64_t gstatus;

    if ( mctc == NULL )
        return 0;

    gstatus = mca_rdmsr(MSR_IA32_MCG_STATUS);

    /*
     * FIXME: When RIPV = EIPV = 0, it's a little bit tricky. It may be an
     * asynchronic error, currently we have no way to precisely locate
     * whether the error occur at guest or hypervisor.
     * To avoid handling error in wrong way, we treat it as unrecovered.
     *
     * Another unrecovered case is RIPV = 0 while in hypervisor
     * since Xen is not pre-emptible.
     */
    if ( !(gstatus & MCG_STATUS_RIPV) &&
         (!(gstatus & MCG_STATUS_EIPV) || !guest_mode(regs)) )
        return -1;

    return mce_action(regs, mctc) == MCER_RESET ? -1 : 0;
}

/* Shared #MC handler. */
void mcheck_cmn_handler(const struct cpu_user_regs *regs)
{
    static DEFINE_MCE_BARRIER(mce_trap_bar);
    static atomic_t severity_cpu = ATOMIC_INIT(-1);
    static atomic_t found_error = ATOMIC_INIT(0);
    static cpumask_t mce_fatal_cpus;
    struct mca_banks *bankmask = mca_allbanks;
    unsigned int cpu = smp_processor_id();
    struct mca_banks *clear_bank = per_cpu(mce_clear_banks, cpu);
    uint64_t gstatus;
    mctelem_cookie_t mctc = NULL;
    struct mca_summary bs;
    bool bcast, lmce;

    mce_spin_lock(&mce_logout_lock);

    if ( clear_bank != NULL )
        memset(clear_bank->bank_map, 0x0,
               sizeof(long) * BITS_TO_LONGS(clear_bank->num));
    mctc = mcheck_mca_logout(MCA_MCE_SCAN, bankmask, &bs, clear_bank);
    lmce = bs.lmce;
    bcast = mce_broadcast && !lmce;

    if ( bs.errcnt )
    {
        /*
         * Uncorrected errors must be dealt with in softirq context.
         */
        if ( bs.uc || bs.pcc )
        {
            add_taint(TAINT_MACHINE_CHECK);
            if ( mctc )
                mctelem_defer(mctc, lmce);
            /*
             * For PCC=1 and can't be recovered, context is lost, so
             * reboot now without clearing the banks, and deal with
             * the telemetry after reboot (the MSRs are sticky)
             */
            if ( bs.pcc || !bs.recoverable )
                cpumask_set_cpu(cpu, &mce_fatal_cpus);
        }
        else if ( mctc != NULL )
            mctelem_commit(mctc);
        atomic_set(&found_error, 1);

        /* The last CPU will be take check/clean-up etc */
        atomic_set(&severity_cpu, cpu);

        mce_printk(MCE_CRITICAL, "MCE: clear_bank map %lx on CPU%u\n",
                   *((unsigned long *)clear_bank), cpu);
        if ( clear_bank != NULL )
            mcheck_mca_clearbanks(clear_bank);
    }
    else if ( mctc != NULL )
        mctelem_dismiss(mctc);
    mce_spin_unlock(&mce_logout_lock);

    mce_barrier_enter(&mce_trap_bar, bcast);
    if ( mctc != NULL && mce_urgent_action(regs, mctc) )
        cpumask_set_cpu(cpu, &mce_fatal_cpus);
    mce_barrier_exit(&mce_trap_bar, bcast);

    /*
     * Wait until everybody has processed the trap.
     */
    mce_barrier_enter(&mce_trap_bar, bcast);
    if ( lmce || atomic_read(&severity_cpu) == cpu )
    {
        /*
         * According to SDM, if no error bank found on any cpus,
         * something unexpected happening, we can't do any
         * recovery job but to reset the system.
         */
        if ( atomic_read(&found_error) == 0 )
            mc_panic("MCE: No CPU found valid MCE, need reset");
        if ( !cpumask_empty(&mce_fatal_cpus) )
        {
            char ebuf[96];

            snprintf(ebuf, sizeof(ebuf),
                     "MCE: Fatal error happened on CPUs %*pb",
                     CPUMASK_PR(&mce_fatal_cpus));

            mc_panic(ebuf);
        }
        atomic_set(&found_error, 0);
        atomic_set(&severity_cpu, -1);
    }
    mce_barrier_exit(&mce_trap_bar, bcast);

    /* Clear flags after above fatal check */
    mce_barrier_enter(&mce_trap_bar, bcast);
    gstatus = mca_rdmsr(MSR_IA32_MCG_STATUS);
    if ( (gstatus & MCG_STATUS_MCIP) != 0 )
    {
        mce_printk(MCE_CRITICAL, "MCE: Clear MCIP@ last step");
        mca_wrmsr(MSR_IA32_MCG_STATUS, 0);
    }
    mce_barrier_exit(&mce_trap_bar, bcast);

    raise_softirq(MACHINE_CHECK_SOFTIRQ);
}

void mcheck_mca_clearbanks(struct mca_banks *bankmask)
{
    int i;

    for ( i = 0; i < this_cpu(nr_mce_banks); i++ )
    {
        if ( !mcabanks_test(i, bankmask) )
            continue;
        mcabank_clear(i);
    }
}

/*check the existence of Machine Check*/
bool mce_available(const struct cpuinfo_x86 *c)
{
    return cpu_has(c, X86_FEATURE_MCE) && cpu_has(c, X86_FEATURE_MCA);
}

/*
 * Check if bank 0 is usable for MCE. It isn't for Intel P6 family
 * before model 0x1a.
 */
unsigned int mce_firstbank(struct cpuinfo_x86 *c)
{
    return c->x86 == 6 &&
           c->x86_vendor == X86_VENDOR_INTEL && c->x86_model < 0x1a;
}

int show_mca_info(int inited, struct cpuinfo_x86 *c)
{
    static enum mcheck_type g_type = mcheck_unset;

    if ( inited != g_type )
    {
        char prefix[20];
        static const char *const type_str[] = {
            [mcheck_amd_famXX] = "AMD",
            [mcheck_amd_k8] = "AMD K8",
            [mcheck_intel] = "Intel"
        };

        snprintf(prefix, ARRAY_SIZE(prefix), "%sCPU%u: ",
                 g_type != mcheck_unset ? XENLOG_WARNING : XENLOG_INFO,
                 smp_processor_id());
        BUG_ON(inited >= ARRAY_SIZE(type_str));
        switch ( inited )
        {
        default:
            printk("%s%s machine check reporting enabled\n",
                   prefix, type_str[inited]);
            break;

        case mcheck_amd_famXX:
            printk("%s%s Fam%xh machine check reporting enabled\n",
                   prefix, type_str[inited], c->x86);
            break;

        case mcheck_none:
            printk("%sNo machine check initialization\n", prefix);
            break;
        }
        g_type = inited;
    }

    return 0;
}

static void set_poll_bankmask(struct cpuinfo_x86 *c)
{
    int cpu = smp_processor_id();
    struct mca_banks *mb;

    mb = per_cpu(poll_bankmask, cpu);
    BUG_ON(!mb);

    if ( cmci_support && opt_mce )
    {
        const struct mca_banks *cmci = per_cpu(no_cmci_banks, cpu);

        if ( unlikely(cmci->num < mb->num) )
            bitmap_fill(mb->bank_map, mb->num);
        bitmap_copy(mb->bank_map, cmci->bank_map, min(mb->num, cmci->num));
    }
    else
    {
        bitmap_copy(mb->bank_map, mca_allbanks->bank_map,
                    per_cpu(nr_mce_banks, cpu));
        if ( mce_firstbank(c) )
            mcabanks_clear(0, mb);
    }
}

/* The perbank ctl/status init is platform specific because of AMD's quirk */
static int mca_cap_init(void)
{
    uint64_t msr_content;
    unsigned int nr, cpu = smp_processor_id();

    rdmsrl(MSR_IA32_MCG_CAP, msr_content);

    if ( msr_content & MCG_CTL_P ) /* Control register present ? */
        wrmsrl(MSR_IA32_MCG_CTL, 0xffffffffffffffffULL);

    per_cpu(nr_mce_banks, cpu) = nr = MASK_EXTR(msr_content, MCG_CAP_COUNT);

    if ( !nr )
    {
        printk(XENLOG_INFO
               "CPU%u: No MCE banks present. Machine check support disabled\n",
               cpu);
        return -ENODEV;
    }

    /* mcabanks_alloc depends on nr_mce_banks */
    if ( !mca_allbanks || nr > mca_allbanks->num )
    {
        unsigned int i;
        struct mca_banks *all = mcabanks_alloc(nr);

        if ( !all )
            return -ENOMEM;
        for ( i = 0; i < nr; i++ )
            mcabanks_set(i, mca_allbanks);
        mcabanks_free(xchg(&mca_allbanks, all));
    }

    return 0;
}

static void cpu_bank_free(unsigned int cpu)
{
    struct mca_banks *poll = per_cpu(poll_bankmask, cpu);
    struct mca_banks *clr = per_cpu(mce_clear_banks, cpu);

    mcabanks_free(poll);
    mcabanks_free(clr);

    per_cpu(poll_bankmask, cpu) = NULL;
    per_cpu(mce_clear_banks, cpu) = NULL;
}

static int cpu_bank_alloc(unsigned int cpu)
{
    unsigned int nr = per_cpu(nr_mce_banks, cpu);
    struct mca_banks *poll = per_cpu(poll_bankmask, cpu) ?: mcabanks_alloc(nr);
    struct mca_banks *clr = per_cpu(mce_clear_banks, cpu) ?: mcabanks_alloc(nr);

    if ( !poll || !clr )
    {
        mcabanks_free(poll);
        mcabanks_free(clr);
        return -ENOMEM;
    }

    per_cpu(poll_bankmask, cpu) = poll;
    per_cpu(mce_clear_banks, cpu) = clr;
    return 0;
}

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = cpu_bank_alloc(cpu);
        break;

    case CPU_UP_CANCELED:
    case CPU_DEAD:
        if ( !park_offline_cpus )
            cpu_bank_free(cpu);
        break;

    case CPU_REMOVE:
        if ( park_offline_cpus )
            cpu_bank_free(cpu);
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

/* This has to be run for each processor */
void mcheck_init(struct cpuinfo_x86 *c, bool bsp)
{
    enum mcheck_type inited = mcheck_none;
    unsigned int cpu = smp_processor_id();

    if ( !opt_mce )
    {
        if ( bsp )
            printk(XENLOG_INFO "MCE support disabled by bootparam\n");
        return;
    }

    if ( !mce_available(c) )
    {
        printk(XENLOG_INFO "CPU%i: No machine check support available\n", cpu);
        return;
    }

    /*Hardware Enable */
    if ( mca_cap_init() )
        return;

    if ( !bsp )
    {
        per_cpu(poll_bankmask, cpu)->num = per_cpu(nr_mce_banks, cpu);
        per_cpu(mce_clear_banks, cpu)->num = per_cpu(nr_mce_banks, cpu);
    }
    else if ( cpu_bank_alloc(cpu) )
        panic("Insufficient memory for MCE bank allocations\n");

    switch ( c->x86_vendor )
    {
    case X86_VENDOR_AMD:
    case X86_VENDOR_HYGON:
        inited = amd_mcheck_init(c);
        break;

    case X86_VENDOR_INTEL:
        switch ( c->x86 )
        {
        case 6:
        case 15:
            inited = intel_mcheck_init(c, bsp);
            break;
        }
        break;

    default:
        break;
    }

    show_mca_info(inited, c);
    if ( inited == mcheck_none || inited == mcheck_unset )
        goto out;

    intpose_init();

    if ( bsp )
    {
        mctelem_init(sizeof(struct mc_info));
        register_cpu_notifier(&cpu_nfb);
    }

    /* Turn on MCE now */
    set_in_cr4(X86_CR4_MCE);

    set_poll_bankmask(c);

    return;
 out:
    if ( bsp )
    {
        cpu_bank_free(smp_processor_id());
        mcabanks_free(mca_allbanks);
        mca_allbanks = NULL;
    }
}

static void mcinfo_clear(struct mc_info *mi)
{
    memset(mi, 0, sizeof(struct mc_info));
    x86_mcinfo_nentries(mi) = 0;
}

void *x86_mcinfo_reserve(struct mc_info *mi,
                         unsigned int size, unsigned int type)
{
    int i;
    unsigned long end1, end2;
    struct mcinfo_common *mic_base, *mic_index;

    mic_index = mic_base = x86_mcinfo_first(mi);

    /* go to first free entry */
    for ( i = 0; i < x86_mcinfo_nentries(mi); i++ )
        mic_index = x86_mcinfo_next(mic_index);

    /* check if there is enough size */
    end1 = (unsigned long)((uint8_t *)mic_base + sizeof(struct mc_info));
    end2 = (unsigned long)((uint8_t *)mic_index + size);

    if ( end1 < end2 )
    {
        mce_printk(MCE_CRITICAL,
                   "mcinfo_add: No space left in mc_info\n");
        return NULL;
    }

    /* there's enough space. add entry. */
    x86_mcinfo_nentries(mi)++;

    memset(mic_index, 0, size);
    mic_index->size = size;
    mic_index->type = type;

    return mic_index;
}

static void x86_mcinfo_apei_save(
    struct mcinfo_global *mc_global, struct mcinfo_bank *mc_bank)
{
    struct mce m;

    memset(&m, 0, sizeof(struct mce));

    m.cpu = mc_global->mc_coreid;
    m.cpuvendor = boot_cpu_data.x86_vendor;
    m.cpuid = cpuid_eax(1);
    m.socketid = mc_global->mc_socketid;
    m.apicid = mc_global->mc_apicid;

    m.mcgstatus = mc_global->mc_gstatus;
    m.status = mc_bank->mc_status;
    m.misc = mc_bank->mc_misc;
    m.addr = mc_bank->mc_addr;
    m.bank = mc_bank->mc_bank;

    apei_write_mce(&m);
}

/*
 * Dump machine check information in a format,
 * mcelog can parse. This is used only when
 * Dom0 does not take the notification.
 */
void x86_mcinfo_dump(struct mc_info *mi)
{
    struct mcinfo_common *mic = NULL;
    struct mcinfo_global *mc_global;
    struct mcinfo_bank *mc_bank;

    /* first print the global info */
    x86_mcinfo_lookup(mic, mi, MC_TYPE_GLOBAL);
    if ( mic == NULL )
        return;
    mc_global = (struct mcinfo_global *)mic;
    if ( mc_global->mc_flags & MC_FLAG_MCE )
        printk(XENLOG_WARNING
               "CPU%d: Machine Check Exception: %16"PRIx64"\n",
               mc_global->mc_coreid, mc_global->mc_gstatus);
    else if ( mc_global->mc_flags & MC_FLAG_CMCI )
        printk(XENLOG_WARNING "CMCI occurred on CPU %d.\n",
               mc_global->mc_coreid);
    else if ( mc_global->mc_flags & MC_FLAG_POLLED )
        printk(XENLOG_WARNING "POLLED occurred on CPU %d.\n",
               mc_global->mc_coreid);

    /* then the bank information */
    x86_mcinfo_lookup(mic, mi, MC_TYPE_BANK); /* finds the first entry */
    do {
        if ( mic == NULL )
            return;
        if ( mic->type != MC_TYPE_BANK )
            goto next;

        mc_bank = (struct mcinfo_bank *)mic;

        printk(XENLOG_WARNING "Bank %d: %16"PRIx64,
               mc_bank->mc_bank,
               mc_bank->mc_status);
        if ( mc_bank->mc_status & MCi_STATUS_MISCV )
            printk("[%16"PRIx64"]", mc_bank->mc_misc);
        if ( mc_bank->mc_status & MCi_STATUS_ADDRV )
            printk(" at %16"PRIx64, mc_bank->mc_addr);
        printk("\n");

        if ( is_mc_panic )
            x86_mcinfo_apei_save(mc_global, mc_bank);

 next:
        mic = x86_mcinfo_next(mic); /* next entry */
        if ( (mic == NULL) || (mic->size == 0) )
            break;
    } while ( 1 );
}

static void do_mc_get_cpu_info(void *v)
{
    int cpu = smp_processor_id();
    int cindex, cpn;
    struct cpuinfo_x86 *c;
    xen_mc_logical_cpu_t *log_cpus, *xcp;
    uint32_t junk, ebx;

    log_cpus = v;
    c = &cpu_data[cpu];
    cindex = 0;
    cpn = cpu - 1;

    /*
     * Deal with sparse masks, condensed into a contig array.
     */
    while ( cpn >= 0 )
    {
        if ( cpu_online(cpn) )
            cindex++;
        cpn--;
    }

    xcp = &log_cpus[cindex];
    c = &cpu_data[cpu];
    xcp->mc_cpunr = cpu;
    x86_mc_get_cpu_info(cpu, &xcp->mc_chipid,
                        &xcp->mc_coreid, &xcp->mc_threadid,
                        &xcp->mc_apicid, &xcp->mc_ncores,
                        &xcp->mc_ncores_active, &xcp->mc_nthreads);
    xcp->mc_cpuid_level = c->cpuid_level;
    xcp->mc_family = c->x86;
    xcp->mc_vendor = c->x86_vendor;
    xcp->mc_model = c->x86_model;
    xcp->mc_step = c->x86_mask;
    xcp->mc_cache_size = c->x86_cache_size;
    xcp->mc_cache_alignment = c->x86_cache_alignment;
    memcpy(xcp->mc_vendorid, c->x86_vendor_id, sizeof xcp->mc_vendorid);
    memcpy(xcp->mc_brandid, c->x86_model_id, sizeof xcp->mc_brandid);
    memcpy(xcp->mc_cpu_caps, c->x86_capability, sizeof xcp->mc_cpu_caps);

    /*
     * This part needs to run on the CPU itself.
     */
    xcp->mc_nmsrvals = __MC_NMSRS;
    xcp->mc_msrvalues[0].reg = MSR_IA32_MCG_CAP;
    rdmsrl(MSR_IA32_MCG_CAP, xcp->mc_msrvalues[0].value);

    if ( c->cpuid_level >= 1 )
    {
        cpuid(1, &junk, &ebx, &junk, &junk);
        xcp->mc_clusterid = (ebx >> 24) & 0xff;
    }
    else
        xcp->mc_clusterid = get_apic_id();
}

void x86_mc_get_cpu_info(unsigned cpu, uint32_t *chipid, uint16_t *coreid,
                         uint16_t *threadid, uint32_t *apicid,
                         unsigned *ncores, unsigned *ncores_active,
                         unsigned *nthreads)
{
    struct cpuinfo_x86 *c;

    *apicid = cpu_physical_id(cpu);
    c = &cpu_data[cpu];
    if ( c->apicid == BAD_APICID )
    {
        *chipid = cpu;
        *coreid = 0;
        *threadid = 0;
        if ( ncores != NULL )
            *ncores = 1;
        if ( ncores_active != NULL )
            *ncores_active = 1;
        if ( nthreads != NULL )
            *nthreads = 1;
    }
    else
    {
        *chipid = c->phys_proc_id;
        if ( c->x86_max_cores > 1 )
            *coreid = c->cpu_core_id;
        else
            *coreid = 0;
        *threadid = c->apicid & ((1 << (c->x86_num_siblings - 1)) - 1);
        if ( ncores != NULL )
            *ncores = c->x86_max_cores;
        if ( ncores_active != NULL )
            *ncores_active = c->booted_cores;
        if ( nthreads != NULL )
            *nthreads = c->x86_num_siblings;
    }
}

#define INTPOSE_NENT 50

static struct intpose_ent {
    unsigned int cpu_nr;
    uint64_t msr;
    uint64_t val;
} intpose_arr[INTPOSE_NENT];

static void intpose_init(void)
{
    static int done;
    int i;

    if ( done++ > 0 )
        return;

    for ( i = 0; i < INTPOSE_NENT; i++ )
        intpose_arr[i].cpu_nr = -1;

}

struct intpose_ent *intpose_lookup(unsigned int cpu_nr, uint64_t msr,
                                   uint64_t *valp)
{
    int i;

    for ( i = 0; i < INTPOSE_NENT; i++ )
    {
        if ( intpose_arr[i].cpu_nr == cpu_nr && intpose_arr[i].msr == msr )
        {
            if ( valp != NULL )
                *valp = intpose_arr[i].val;
            return &intpose_arr[i];
        }
    }

    return NULL;
}

static void intpose_add(unsigned int cpu_nr, uint64_t msr, uint64_t val)
{
    struct intpose_ent *ent = intpose_lookup(cpu_nr, msr, NULL);
    int i;

    if ( ent )
    {
        ent->val = val;
        return;
    }

    for ( i = 0, ent = &intpose_arr[0]; i < INTPOSE_NENT; i++, ent++ )
    {
        if ( ent->cpu_nr == -1 )
        {
            ent->cpu_nr = cpu_nr;
            ent->msr = msr;
            ent->val = val;
            return;
        }
    }

    printk("intpose_add: interpose array full - request dropped\n");
}

bool intpose_inval(unsigned int cpu_nr, uint64_t msr)
{
    struct intpose_ent *ent = intpose_lookup(cpu_nr, msr, NULL);

    if ( !ent )
        return false;

    ent->cpu_nr = -1;
    return true;
}

#define IS_MCA_BANKREG(r, cpu) \
    ((r) >= MSR_IA32_MC0_CTL && \
     (r) <= MSR_IA32_MCx_MISC(per_cpu(nr_mce_banks, cpu) - 1) && \
     ((r) - MSR_IA32_MC0_CTL) % 4) /* excludes MCi_CTL */

static bool x86_mc_msrinject_verify(struct xen_mc_msrinject *mci)
{
    const struct cpuinfo_x86 *c = &cpu_data[mci->mcinj_cpunr];
    int i, errs = 0;

    for ( i = 0; i < mci->mcinj_count; i++ )
    {
        uint64_t reg = mci->mcinj_msr[i].reg;
        const char *reason = NULL;

        if ( IS_MCA_BANKREG(reg, mci->mcinj_cpunr) )
        {
            if ( c->x86_vendor == X86_VENDOR_AMD )
            {
                /*
                 * On AMD we can set MCi_STATUS_WREN in the
                 * HWCR MSR to allow non-zero writes to banks
                 * MSRs not to #GP.  The injector in dom0
                 * should set that bit, but we detect when it
                 * is necessary and set it as a courtesy to
                 * avoid #GP in the hypervisor.
                 */
                mci->mcinj_flags |=
                    _MC_MSRINJ_F_REQ_HWCR_WREN;
                continue;
            }
            else
            {
                /*
                 * No alternative but to interpose, so require
                 * that the injector specified as such.
                 */
                if ( !(mci->mcinj_flags & MC_MSRINJ_F_INTERPOSE) )
                    reason = "must specify interposition";
            }
        }
        else
        {
            switch ( reg )
            {
            /* MSRs acceptable on all x86 cpus */
            case MSR_IA32_MCG_STATUS:
                break;

            case MSR_F10_MC4_MISC1:
            case MSR_F10_MC4_MISC2:
            case MSR_F10_MC4_MISC3:
                if ( c->x86_vendor != X86_VENDOR_AMD )
                    reason = "only supported on AMD";
                else if ( c->x86 < 0x10 )
                    reason = "only supported on AMD Fam10h+";
                break;

            /* MSRs that the HV will take care of */
            case MSR_K8_HWCR:
                if ( c->x86_vendor & (X86_VENDOR_AMD | X86_VENDOR_HYGON) )
                    reason = "HV will operate HWCR";
                else
                    reason = "only supported on AMD or Hygon";
                break;

            default:
                reason = "not a recognized MCA MSR";
                break;
            }
        }

        if ( reason != NULL )
        {
            printk("HV MSR INJECT ERROR: MSR %#Lx %s\n",
                   (unsigned long long)mci->mcinj_msr[i].reg, reason);
            errs++;
        }
    }

    return !errs;
}

static uint64_t x86_mc_hwcr_wren(void)
{
    uint64_t old;

    rdmsrl(MSR_K8_HWCR, old);

    if ( !(old & K8_HWCR_MCi_STATUS_WREN) )
    {
        uint64_t new = old | K8_HWCR_MCi_STATUS_WREN;
        wrmsrl(MSR_K8_HWCR, new);
    }

    return old;
}

static void x86_mc_hwcr_wren_restore(uint64_t hwcr)
{
    if ( !(hwcr & K8_HWCR_MCi_STATUS_WREN) )
        wrmsrl(MSR_K8_HWCR, hwcr);
}

static void x86_mc_msrinject(void *data)
{
    struct xen_mc_msrinject *mci = data;
    struct mcinfo_msr *msr;
    uint64_t hwcr = 0;
    int intpose;
    int i;

    if ( mci->mcinj_flags & _MC_MSRINJ_F_REQ_HWCR_WREN )
        hwcr = x86_mc_hwcr_wren();

    intpose = (mci->mcinj_flags & MC_MSRINJ_F_INTERPOSE) != 0;

    for ( i = 0, msr = &mci->mcinj_msr[0]; i < mci->mcinj_count; i++, msr++ )
    {
        printk("HV MSR INJECT (%s) target %u actual %u MSR %#Lx <-- %#Lx\n",
               intpose ? "interpose" : "hardware",
               mci->mcinj_cpunr, smp_processor_id(),
               (unsigned long long)msr->reg,
               (unsigned long long)msr->value);

        if ( intpose )
            intpose_add(mci->mcinj_cpunr, msr->reg, msr->value);
        else
            wrmsrl(msr->reg, msr->value);
    }

    if ( mci->mcinj_flags & _MC_MSRINJ_F_REQ_HWCR_WREN )
        x86_mc_hwcr_wren_restore(hwcr);
}

/*ARGSUSED*/
static void x86_mc_mceinject(void *data)
{
    printk("Simulating #MC on cpu %d\n", smp_processor_id());
    __asm__ __volatile__("int $0x12");
}

#if BITS_PER_LONG == 64

#define ID2COOKIE(id) ((mctelem_cookie_t)(id))
#define COOKIE2ID(c) ((uint64_t)(c))

#elif defined(BITS_PER_LONG)
#error BITS_PER_LONG has unexpected value
#else
#error BITS_PER_LONG definition absent
#endif

# include <compat/arch-x86/xen-mca.h>

# define xen_mcinfo_msr              mcinfo_msr
CHECK_mcinfo_msr;
# undef xen_mcinfo_msr
# undef CHECK_mcinfo_msr
# define CHECK_mcinfo_msr            struct mcinfo_msr

# define xen_mcinfo_common           mcinfo_common
CHECK_mcinfo_common;
# undef xen_mcinfo_common
# undef CHECK_mcinfo_common
# define CHECK_mcinfo_common         struct mcinfo_common

CHECK_FIELD_(struct, mc_fetch, flags);
CHECK_FIELD_(struct, mc_fetch, fetch_id);
# define CHECK_compat_mc_fetch       struct mc_fetch

CHECK_FIELD_(struct, mc_physcpuinfo, ncpus);
# define CHECK_compat_mc_physcpuinfo struct mc_physcpuinfo

#define CHECK_compat_mc_inject_v2   struct mc_inject_v2
CHECK_mc;
# undef CHECK_compat_mc_fetch
# undef CHECK_compat_mc_physcpuinfo

# define xen_mc_info                 mc_info
CHECK_mc_info;
# undef xen_mc_info

# define xen_mcinfo_global           mcinfo_global
CHECK_mcinfo_global;
# undef xen_mcinfo_global

# define xen_mcinfo_bank             mcinfo_bank
CHECK_mcinfo_bank;
# undef xen_mcinfo_bank

# define xen_mcinfo_extended         mcinfo_extended
CHECK_mcinfo_extended;
# undef xen_mcinfo_extended

# define xen_mcinfo_recovery         mcinfo_recovery
# define xen_cpu_offline_action      cpu_offline_action
# define xen_page_offline_action     page_offline_action
CHECK_mcinfo_recovery;
# undef xen_cpu_offline_action
# undef xen_page_offline_action
# undef xen_mcinfo_recovery

/* Machine Check Architecture Hypercall */
long do_mca(XEN_GUEST_HANDLE_PARAM(xen_mc_t) u_xen_mc)
{
    long ret = 0;
    struct xen_mc curop, *op = &curop;
    struct vcpu *v = current;
    union {
        struct xen_mc_fetch *nat;
        struct compat_mc_fetch *cmp;
    } mc_fetch;
    union {
        struct xen_mc_physcpuinfo *nat;
        struct compat_mc_physcpuinfo *cmp;
    } mc_physcpuinfo;
    uint32_t flags, cmdflags;
    int nlcpu;
    xen_mc_logical_cpu_t *log_cpus = NULL;
    mctelem_cookie_t mctc;
    mctelem_class_t which;
    unsigned int target;
    struct xen_mc_msrinject *mc_msrinject;
    struct xen_mc_mceinject *mc_mceinject;

    ret = xsm_do_mca(XSM_PRIV);
    if ( ret )
        return x86_mcerr("", ret);

    if ( copy_from_guest(op, u_xen_mc, 1) )
        return x86_mcerr("do_mca: failed copyin of xen_mc_t", -EFAULT);

    if ( op->interface_version != XEN_MCA_INTERFACE_VERSION )
        return x86_mcerr("do_mca: interface version mismatch", -EACCES);

    switch ( op->cmd )
    {
    case XEN_MC_fetch:
        mc_fetch.nat = &op->u.mc_fetch;
        cmdflags = mc_fetch.nat->flags;

        switch ( cmdflags & (XEN_MC_NONURGENT | XEN_MC_URGENT) )
        {
        case XEN_MC_NONURGENT:
            which = MC_NONURGENT;
            break;

        case XEN_MC_URGENT:
            which = MC_URGENT;
            break;

        default:
            return x86_mcerr("do_mca fetch: bad cmdflags", -EINVAL);
        }

        flags = XEN_MC_OK;

        if ( cmdflags & XEN_MC_ACK )
        {
            mctelem_cookie_t cookie = ID2COOKIE(mc_fetch.nat->fetch_id);
            mctelem_ack(which, cookie);
        }
        else
        {
            if ( !is_pv_32bit_vcpu(v)
                 ? guest_handle_is_null(mc_fetch.nat->data)
                 : compat_handle_is_null(mc_fetch.cmp->data) )
                return x86_mcerr("do_mca fetch: guest buffer "
                                 "invalid", -EINVAL);

            mctc = mctelem_consume_oldest_begin(which);
            if ( mctc )
            {
                struct mc_info *mcip = mctelem_dataptr(mctc);
                if ( !is_pv_32bit_vcpu(v)
                     ? copy_to_guest(mc_fetch.nat->data, mcip, 1)
                     : copy_to_compat(mc_fetch.cmp->data, mcip, 1) )
                {
                    ret = -EFAULT;
                    flags |= XEN_MC_FETCHFAILED;
                    mc_fetch.nat->fetch_id = 0;
                }
                else
                    mc_fetch.nat->fetch_id = COOKIE2ID(mctc);
                mctelem_consume_oldest_end(mctc);
            }
            else
            {
                /* There is no data */
                flags |= XEN_MC_NODATA;
                mc_fetch.nat->fetch_id = 0;
            }

            mc_fetch.nat->flags = flags;
            if (copy_to_guest(u_xen_mc, op, 1) != 0)
                ret = -EFAULT;
        }

        break;

    case XEN_MC_notifydomain:
        return x86_mcerr("do_mca notify unsupported", -EINVAL);

    case XEN_MC_physcpuinfo:
        mc_physcpuinfo.nat = &op->u.mc_physcpuinfo;
        nlcpu = num_online_cpus();

        if ( !is_pv_32bit_vcpu(v)
             ? !guest_handle_is_null(mc_physcpuinfo.nat->info)
             : !compat_handle_is_null(mc_physcpuinfo.cmp->info) )
        {
            if ( mc_physcpuinfo.nat->ncpus <= 0 )
                return x86_mcerr("do_mca cpuinfo: ncpus <= 0",
                                 -EINVAL);
            nlcpu = min(nlcpu, (int)mc_physcpuinfo.nat->ncpus);
            log_cpus = xmalloc_array(xen_mc_logical_cpu_t, nlcpu);
            if ( log_cpus == NULL )
                return x86_mcerr("do_mca cpuinfo", -ENOMEM);
            on_each_cpu(do_mc_get_cpu_info, log_cpus, 1);
            if ( !is_pv_32bit_vcpu(v)
                 ? copy_to_guest(mc_physcpuinfo.nat->info, log_cpus, nlcpu)
                 : copy_to_compat(mc_physcpuinfo.cmp->info, log_cpus, nlcpu) )
                ret = -EFAULT;
            xfree(log_cpus);
        }

        mc_physcpuinfo.nat->ncpus = nlcpu;

        if ( copy_to_guest(u_xen_mc, op, 1) )
            return x86_mcerr("do_mca cpuinfo", -EFAULT);

        break;

    case XEN_MC_msrinject:
        if ( !mca_allbanks || !mca_allbanks->num )
            return x86_mcerr("do_mca inject", -ENODEV);

        mc_msrinject = &op->u.mc_msrinject;
        target = mc_msrinject->mcinj_cpunr;

        if ( target >= nr_cpu_ids )
            return x86_mcerr("do_mca inject: bad target", -EINVAL);

        if ( !cpu_online(target) )
            return x86_mcerr("do_mca inject: target offline",
                             -EINVAL);

        if ( !per_cpu(nr_mce_banks, target) )
            return x86_mcerr("do_mca inject: no banks", -ENOENT);

        if ( mc_msrinject->mcinj_count == 0 )
            return 0;

        if ( mc_msrinject->mcinj_flags & MC_MSRINJ_F_GPADDR )
        {
            domid_t domid;
            struct domain *d;
            struct mcinfo_msr *msr;
            unsigned int i;
            paddr_t gaddr;
            unsigned long gfn, mfn;
            p2m_type_t t;

            domid = (mc_msrinject->mcinj_domid == DOMID_SELF) ?
                    current->domain->domain_id : mc_msrinject->mcinj_domid;
            if ( domid >= DOMID_FIRST_RESERVED )
                return x86_mcerr("do_mca inject: incompatible flag "
                                 "MC_MSRINJ_F_GPADDR with domain %d",
                                 -EINVAL, domid);

            d = get_domain_by_id(domid);
            if ( d == NULL )
                return x86_mcerr("do_mca inject: bad domain id %d",
                                 -EINVAL, domid);

            for ( i = 0, msr = &mc_msrinject->mcinj_msr[0];
                  i < mc_msrinject->mcinj_count;
                  i++, msr++ )
            {
                gaddr = msr->value;
                gfn = PFN_DOWN(gaddr);
                mfn = mfn_x(get_gfn(d, gfn, &t));

                if ( mfn == mfn_x(INVALID_MFN) )
                {
                    put_gfn(d, gfn);
                    put_domain(d);
                    return x86_mcerr("do_mca inject: bad gfn %#lx of domain %d",
                                     -EINVAL, gfn, domid);
                }

                msr->value = pfn_to_paddr(mfn) | (gaddr & (PAGE_SIZE - 1));

                put_gfn(d, gfn);
            }

            put_domain(d);
        }

        if ( !x86_mc_msrinject_verify(mc_msrinject) )
            return x86_mcerr("do_mca inject: illegal MSR", -EINVAL);

        add_taint(TAINT_ERROR_INJECT);

        on_selected_cpus(cpumask_of(target), x86_mc_msrinject,
                         mc_msrinject, 1);

        break;

    case XEN_MC_mceinject:
        if ( !mca_allbanks || !mca_allbanks->num )
            return x86_mcerr("do_mca #MC", -ENODEV);

        mc_mceinject = &op->u.mc_mceinject;
        target = mc_mceinject->mceinj_cpunr;

        if ( target >= nr_cpu_ids )
            return x86_mcerr("do_mca #MC: bad target", -EINVAL);

        if ( !cpu_online(target) )
            return x86_mcerr("do_mca #MC: target offline", -EINVAL);

        if ( !per_cpu(nr_mce_banks, target) )
            return x86_mcerr("do_mca #MC: no banks", -ENOENT);

        add_taint(TAINT_ERROR_INJECT);

        if ( mce_broadcast )
            on_each_cpu(x86_mc_mceinject, mc_mceinject, 1);
        else
            on_selected_cpus(cpumask_of(target), x86_mc_mceinject,
                             mc_mceinject, 1);
        break;

    case XEN_MC_inject_v2:
    {
        const cpumask_t *cpumap;
        cpumask_var_t cmv;
        bool broadcast = op->u.mc_inject_v2.flags & XEN_MC_INJECT_CPU_BROADCAST;

        if ( !mca_allbanks || !mca_allbanks->num )
            return x86_mcerr("do_mca #MC", -ENODEV);

        if ( broadcast )
            cpumap = &cpu_online_map;
        else
        {
            ret = xenctl_bitmap_to_cpumask(&cmv, &op->u.mc_inject_v2.cpumap);
            if ( ret )
                break;
            cpumap = cmv;
            if ( !cpumask_intersects(cpumap, &cpu_online_map) )
            {
                free_cpumask_var(cmv);
                ret = x86_mcerr("No online CPU passed\n", -EINVAL);
                break;
            }
            if ( !cpumask_subset(cpumap, &cpu_online_map) )
                dprintk(XENLOG_INFO,
                        "Not all required CPUs are online\n");
        }

        for_each_cpu(target, cpumap)
            if ( cpu_online(target) && !per_cpu(nr_mce_banks, target) )
            {
                ret = x86_mcerr("do_mca #MC: CPU%u has no banks",
                                -ENOENT, target);
                break;
            }
        if ( ret )
            break;

        switch ( op->u.mc_inject_v2.flags & XEN_MC_INJECT_TYPE_MASK )
        {
        case XEN_MC_INJECT_TYPE_MCE:
            if ( mce_broadcast &&
                 !cpumask_equal(cpumap, &cpu_online_map) )
                printk("Not trigger MCE on all CPUs, may HANG!\n");
            on_selected_cpus(cpumap, x86_mc_mceinject, NULL, 1);
            break;

        case XEN_MC_INJECT_TYPE_CMCI:
            if ( !cmci_apic_vector )
                ret = x86_mcerr("No CMCI supported in platform\n", -EINVAL);
            else
            {
                if ( cpumask_test_cpu(smp_processor_id(), cpumap) )
                    send_IPI_self(cmci_apic_vector);
                send_IPI_mask(cpumap, cmci_apic_vector);
            }
            break;

        case XEN_MC_INJECT_TYPE_LMCE:
            if ( !lmce_support )
            {
                ret = x86_mcerr("No LMCE support", -EINVAL);
                break;
            }
            if ( broadcast )
            {
                ret = x86_mcerr("Broadcast cannot be used with LMCE", -EINVAL);
                break;
            }
            /* Ensure at most one CPU is specified. */
            if ( nr_cpu_ids > cpumask_next(cpumask_first(cpumap), cpumap) )
            {
                ret = x86_mcerr("More than one CPU specified for LMCE",
                                -EINVAL);
                break;
            }
            on_selected_cpus(cpumap, x86_mc_mceinject, NULL, 1);
            break;

        default:
            ret = x86_mcerr("Wrong mca type\n", -EINVAL);
            break;
        }

        if ( cpumap != &cpu_online_map )
            free_cpumask_var(cmv);

        break;
    }

    default:
        return x86_mcerr("do_mca: bad command", -EINVAL);
    }

    return ret;
}

int mcinfo_dumpped;
static int x86_mcinfo_dump_panic(mctelem_cookie_t mctc)
{
    struct mc_info *mcip = mctelem_dataptr(mctc);

    x86_mcinfo_dump(mcip);
    mcinfo_dumpped++;

    return 0;
}

/* XXX shall we dump commited mc_info?? */
static void mc_panic_dump(void)
{
    int cpu;

    dprintk(XENLOG_ERR, "Begin dump mc_info\n");
    for_each_online_cpu(cpu)
        mctelem_process_deferred(cpu, x86_mcinfo_dump_panic,
                                 mctelem_has_deferred_lmce(cpu));
    dprintk(XENLOG_ERR, "End dump mc_info, %x mcinfo dumped\n", mcinfo_dumpped);
}

void mc_panic(char *s)
{
    is_mc_panic = true;
    console_force_unlock();

    printk("Fatal machine check: %s\n", s);
    printk("\n"
           "****************************************\n"
           "\n"
           "   The processor has reported a hardware error which cannot\n"
           "   be recovered from.  Xen will now reboot the machine.\n");
    mc_panic_dump();
    panic("HARDWARE ERROR\n");
}

/*
 * Machine Check owner judge algorithm:
 * When error happens, all cpus serially read its msr banks.
 * The first CPU who fetches the error bank's info will clear
 * this bank. Later readers can't get any information again.
 * The first CPU is the actual mce_owner
 *
 * For Fatal (pcc=1) error, it might cause machine crash
 * before we're able to log. For avoiding log missing, we adopt two
 * round scanning:
 * Round1: simply scan. If found pcc = 1 or ripv = 0, simply reset.
 * All MCE banks are sticky, when boot up, MCE polling mechanism
 * will help to collect and log those MCE errors.
 * Round2: Do all MCE processing logic as normal.
 */

/* Maybe called in MCE context, no lock, no printk */
static enum mce_result mce_action(const struct cpu_user_regs *regs,
                                  mctelem_cookie_t mctc)
{
    struct mc_info *local_mi;
    enum mce_result bank_result = MCER_NOERROR;
    enum mce_result worst_result = MCER_NOERROR;
    struct mcinfo_common *mic = NULL;
    struct mca_binfo binfo;
    const struct mca_error_handler *handlers = mce_dhandlers;
    unsigned int i, handler_num = mce_dhandler_num;

    /* When in mce context, regs is valid */
    if ( regs )
    {
        handler_num = mce_uhandler_num;
        handlers = mce_uhandlers;
    }

    local_mi = (struct mc_info *)mctelem_dataptr(mctc);
    x86_mcinfo_lookup(mic, local_mi, MC_TYPE_GLOBAL);
    if ( mic == NULL )
    {
        printk(KERN_ERR "MCE: get local buffer entry failed\n ");
        return MCER_CONTINUE;
    }

    memset(&binfo, 0, sizeof(binfo));
    binfo.mig = (struct mcinfo_global *)mic;
    binfo.mi = local_mi;

    /* Processing bank information */
    x86_mcinfo_lookup(mic, local_mi, MC_TYPE_BANK);

    for ( ; bank_result != MCER_RESET && mic && mic->size;
          mic = x86_mcinfo_next(mic) )
    {
        if ( mic->type != MC_TYPE_BANK )
        {
            continue;
        }
        binfo.mib = (struct mcinfo_bank *)mic;
        binfo.bank = binfo.mib->mc_bank;
        bank_result = MCER_NOERROR;
        for ( i = 0; i < handler_num; i++ )
        {
            if ( handlers[i].owned_error(binfo.mib->mc_status) )
            {
                handlers[i].recovery_handler(&binfo, &bank_result, regs);
                if ( worst_result < bank_result )
                    worst_result = bank_result;
                break;
            }
        }
    }

    return worst_result;
}

/*
 * Called from mctelem_process_deferred. Return 1 if the telemetry
 * should be committed for dom0 consumption, 0 if it should be
 * dismissed.
 */
static int mce_delayed_action(mctelem_cookie_t mctc)
{
    enum mce_result result;
    int ret = 0;

    result = mce_action(NULL, mctc);

    switch ( result )
    {
    case MCER_RESET:
        dprintk(XENLOG_ERR, "MCE delayed action failed\n");
        is_mc_panic = true;
        x86_mcinfo_dump(mctelem_dataptr(mctc));
        panic("MCE: Software recovery failed for the UCR\n");
        break;

    case MCER_RECOVERED:
        dprintk(XENLOG_INFO, "MCE: Error is successfully recovered\n");
        ret = 1;
        break;

    case MCER_CONTINUE:
        dprintk(XENLOG_INFO, "MCE: Error can't be recovered, "
                "system is tainted\n");
        x86_mcinfo_dump(mctelem_dataptr(mctc));
        ret = 1;
        break;

    default:
        ret = 0;
        break;
    }
    return ret;
}

/* Softirq Handler for this MCE# processing */
static void mce_softirq(void)
{
    static DEFINE_MCE_BARRIER(mce_inside_bar);
    static DEFINE_MCE_BARRIER(mce_severity_bar);
    static atomic_t severity_cpu;
    int cpu = smp_processor_id();
    unsigned int workcpu;
    bool lmce = mctelem_has_deferred_lmce(cpu);
    bool bcast = mce_broadcast && !lmce;

    mce_printk(MCE_VERBOSE, "CPU%d enter softirq\n", cpu);

    mce_barrier_enter(&mce_inside_bar, bcast);

    if ( !lmce )
    {
        /*
         * Everybody is here. Now let's see who gets to do the
         * recovery work. Right now we just see if there's a CPU
         * that did not have any problems, and pick that one.
         *
         * First, just set a default value: the last CPU who reaches this
         * will overwrite the value and become the default.
         */

        atomic_set(&severity_cpu, cpu);

        mce_barrier_enter(&mce_severity_bar, bcast);
        if ( !mctelem_has_deferred(cpu) )
            atomic_set(&severity_cpu, cpu);
        mce_barrier_exit(&mce_severity_bar, bcast);
    }

    /* We choose severity_cpu for further processing */
    if ( lmce || atomic_read(&severity_cpu) == cpu )
    {

        mce_printk(MCE_VERBOSE, "CPU%d handling errors\n", cpu);

        /*
         * Step1: Fill DOM0 LOG buffer, vMCE injection buffer and
         * vMCE MSRs virtualization buffer
         */

        if ( lmce )
            mctelem_process_deferred(cpu, mce_delayed_action, true);
        else
            for_each_online_cpu(workcpu)
                mctelem_process_deferred(workcpu, mce_delayed_action, false);

        /* Step2: Send Log to DOM0 through vIRQ */
        if ( dom0_vmce_enabled() )
        {
            mce_printk(MCE_VERBOSE, "MCE: send MCE# to DOM0 through virq\n");
            send_global_virq(VIRQ_MCA);
        }
    }

    mce_barrier_exit(&mce_inside_bar, bcast);
}

/*
 * Machine Check owner judge algorithm:
 * When error happens, all cpus serially read its msr banks.
 * The first CPU who fetches the error bank's info will clear
 * this bank. Later readers can't get any infor again.
 * The first CPU is the actual mce_owner
 *
 * For Fatal (pcc=1) error, it might cause machine crash
 * before we're able to log. For avoiding log missing, we adopt two
 * round scanning:
 * Round1: simply scan. If found pcc = 1 or ripv = 0, simply reset.
 * All MCE banks are sticky, when boot up, MCE polling mechanism
 * will help to collect and log those MCE errors.
 * Round2: Do all MCE processing logic as normal.
 */
void mce_handler_init(void)
{
    if ( smp_processor_id() != 0 )
        return;

    /* callback register, do we really need so many callback? */
    /* mce handler data initialization */
    spin_lock_init(&mce_logout_lock);
    open_softirq(MACHINE_CHECK_SOFTIRQ, mce_softirq);
}
