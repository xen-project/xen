/*
 * vmce.c - virtual MCE support
 */

#include <xen/init.h>
#include <xen/types.h>
#include <xen/irq.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/delay.h>
#include <xen/smp.h>
#include <xen/mm.h>
#include <xen/hvm/save.h>
#include <asm/processor.h>
#include <public/sysctl.h>
#include <asm/system.h>
#include <asm/msr.h>
#include <asm/p2m.h>
#include "mce.h"
#include "x86_mca.h"

#define dom_vmce(x)   ((x)->arch.vmca_msrs)

static uint64_t __read_mostly g_mcg_cap;

/* Real value in physical CTL MSR */
static uint64_t __read_mostly h_mcg_ctl;
static uint64_t *__read_mostly h_mci_ctrl;

int vmce_init_msr(struct domain *d)
{
    dom_vmce(d) = xmalloc(struct domain_mca_msrs);
    if ( !dom_vmce(d) )
        return -ENOMEM;

    dom_vmce(d)->mci_ctl = xmalloc_array(uint64_t, nr_mce_banks);
    if ( !dom_vmce(d)->mci_ctl )
    {
        xfree(dom_vmce(d));
        return -ENOMEM;
    }
    memset(dom_vmce(d)->mci_ctl, ~0,
           nr_mce_banks * sizeof(*dom_vmce(d)->mci_ctl));

    dom_vmce(d)->mcg_status = 0x0;
    dom_vmce(d)->mcg_ctl = ~(uint64_t)0x0;
    dom_vmce(d)->nr_injection = 0;

    INIT_LIST_HEAD(&dom_vmce(d)->impact_header);
    spin_lock_init(&dom_vmce(d)->lock);

    return 0;
}

void vmce_destroy_msr(struct domain *d)
{
    if ( !dom_vmce(d) )
        return;
    xfree(dom_vmce(d)->mci_ctl);
    xfree(dom_vmce(d));
    dom_vmce(d) = NULL;
}

void vmce_init_vcpu(struct vcpu *v)
{
    v->arch.mcg_cap = g_mcg_cap;
}

int vmce_restore_vcpu(struct vcpu *v, uint64_t caps)
{
    if ( caps & ~g_mcg_cap & ~MCG_CAP_COUNT & ~MCG_CTL_P )
    {
        dprintk(XENLOG_G_ERR, "%s restore: unsupported MCA capabilities"
                " %#" PRIx64 " for d%d:v%u (supported: %#Lx)\n",
                is_hvm_vcpu(v) ? "HVM" : "PV", caps, v->domain->domain_id,
                v->vcpu_id, g_mcg_cap & ~MCG_CAP_COUNT);
        return -EPERM;
    }

    v->arch.mcg_cap = caps;
    return 0;
}

static int bank_mce_rdmsr(const struct vcpu *v, uint32_t msr, uint64_t *val)
{
    int ret = 1;
    unsigned int bank = (msr - MSR_IA32_MC0_CTL) / 4;
    struct domain_mca_msrs *vmce = dom_vmce(v->domain);
    struct bank_entry *entry;

    *val = 0;

    switch ( msr & (MSR_IA32_MC0_CTL | 3) )
    {
    case MSR_IA32_MC0_CTL:
        if ( bank < nr_mce_banks )
            *val = vmce->mci_ctl[bank] &
                   (h_mci_ctrl ? h_mci_ctrl[bank] : ~0UL);
        mce_printk(MCE_VERBOSE, "MCE: rdmsr MC%u_CTL 0x%"PRIx64"\n",
                   bank, *val);
        break;
    case MSR_IA32_MC0_STATUS:
        /* Only error bank is read. Non-error banks simply return. */
        if ( !list_empty(&vmce->impact_header) )
        {
            entry = list_entry(vmce->impact_header.next,
                               struct bank_entry, list);
            if ( entry->bank == bank )
            {
                *val = entry->mci_status;
                mce_printk(MCE_VERBOSE,
                           "MCE: rd MC%u_STATUS in vMCE# context "
                           "value 0x%"PRIx64"\n", bank, *val);
            }
        }
        break;
    case MSR_IA32_MC0_ADDR:
        if ( !list_empty(&vmce->impact_header) )
        {
            entry = list_entry(vmce->impact_header.next,
                               struct bank_entry, list);
            if ( entry->bank == bank )
            {
                *val = entry->mci_addr;
                mce_printk(MCE_VERBOSE,
                           "MCE: rdmsr MC%u_ADDR in vMCE# context "
                           "0x%"PRIx64"\n", bank, *val);
            }
        }
        break;
    case MSR_IA32_MC0_MISC:
        if ( !list_empty(&vmce->impact_header) )
        {
            entry = list_entry(vmce->impact_header.next,
                               struct bank_entry, list);
            if ( entry->bank == bank )
            {
                *val = entry->mci_misc;
                mce_printk(MCE_VERBOSE,
                           "MCE: rd MC%u_MISC in vMCE# context "
                           "0x%"PRIx64"\n", bank, *val);
            }
        }
        break;
    default:
        switch ( boot_cpu_data.x86_vendor )
        {
        case X86_VENDOR_INTEL:
            ret = intel_mce_rdmsr(v, msr, val);
            break;
        default:
            ret = 0;
            break;
        }
        break;
    }

    return ret;
}

/*
 * < 0: Unsupported and will #GP fault to guest
 * = 0: Not handled, should be handled by other components
 * > 0: Success
 */
int vmce_rdmsr(uint32_t msr, uint64_t *val)
{
    const struct vcpu *cur = current;
    struct domain_mca_msrs *vmce = dom_vmce(cur->domain);
    int ret = 1;

    *val = 0;

    spin_lock(&vmce->lock);

    switch ( msr )
    {
    case MSR_IA32_MCG_STATUS:
        *val = vmce->mcg_status;
        if (*val)
            mce_printk(MCE_VERBOSE,
                       "MCE: rdmsr MCG_STATUS 0x%"PRIx64"\n", *val);
        break;
    case MSR_IA32_MCG_CAP:
        *val = cur->arch.mcg_cap;
        mce_printk(MCE_VERBOSE, "MCE: rdmsr MCG_CAP 0x%"PRIx64"\n",
                   *val);
        break;
    case MSR_IA32_MCG_CTL:
        /* Always 0 if no CTL support */
        if ( cur->arch.mcg_cap & MCG_CTL_P )
            *val = vmce->mcg_ctl & h_mcg_ctl;
        mce_printk(MCE_VERBOSE, "MCE: rdmsr MCG_CTL 0x%"PRIx64"\n",
                   *val);
        break;
    default:
        ret = mce_bank_msr(cur, msr) ? bank_mce_rdmsr(cur, msr, val) : 0;
        break;
    }

    spin_unlock(&vmce->lock);
    return ret;
}

static int bank_mce_wrmsr(struct vcpu *v, u32 msr, u64 val)
{
    int ret = 1;
    unsigned int bank = (msr - MSR_IA32_MC0_CTL) / 4;
    struct domain_mca_msrs *vmce = dom_vmce(v->domain);
    struct bank_entry *entry = NULL;

    switch ( msr & (MSR_IA32_MC0_CTL | 3) )
    {
    case MSR_IA32_MC0_CTL:
        if ( bank < nr_mce_banks )
            vmce->mci_ctl[bank] = val;
        break;
    case MSR_IA32_MC0_STATUS:
        /* Give the first entry of the list, it corresponds to current
         * vMCE# injection. When vMCE# is finished processing by the
         * the guest, this node will be deleted.
         * Only error bank is written. Non-error banks simply return.
         */
        if ( !list_empty(&vmce->impact_header) )
        {
            entry = list_entry(vmce->impact_header.next,
                               struct bank_entry, list);
            if ( entry->bank == bank )
                entry->mci_status = val;
            mce_printk(MCE_VERBOSE,
                       "MCE: wr MC%u_STATUS %"PRIx64" in vMCE#\n",
                       bank, val);
        }
        else
            mce_printk(MCE_VERBOSE,
                       "MCE: wr MC%u_STATUS %"PRIx64"\n", bank, val);
        break;
    case MSR_IA32_MC0_ADDR:
        mce_printk(MCE_QUIET, "MCE: MC%u_ADDR is read-only\n", bank);
        ret = -1;
        break;
    case MSR_IA32_MC0_MISC:
        mce_printk(MCE_QUIET, "MCE: MC%u_MISC is read-only\n", bank);
        ret = -1;
        break;
    default:
        switch ( boot_cpu_data.x86_vendor )
        {
        case X86_VENDOR_INTEL:
            ret = intel_mce_wrmsr(v, msr, val);
            break;
        default:
            ret = 0;
            break;
        }
        break;
    }

    return ret;
}

/*
 * < 0: Unsupported and will #GP fault to guest
 * = 0: Not handled, should be handled by other components
 * > 0: Success
 */
int vmce_wrmsr(u32 msr, u64 val)
{
    struct vcpu *cur = current;
    struct bank_entry *entry = NULL;
    struct domain_mca_msrs *vmce = dom_vmce(cur->domain);
    int ret = 1;

    if ( !g_mcg_cap )
        return 0;

    spin_lock(&vmce->lock);

    switch ( msr )
    {
    case MSR_IA32_MCG_CTL:
        vmce->mcg_ctl = val;
        break;
    case MSR_IA32_MCG_STATUS:
        vmce->mcg_status = val;
        mce_printk(MCE_VERBOSE, "MCE: wrmsr MCG_STATUS %"PRIx64"\n", val);
        /* For HVM guest, this is the point for deleting vMCE injection node */
        if ( is_hvm_vcpu(cur) && (vmce->nr_injection > 0) )
        {
            vmce->nr_injection--; /* Should be 0 */
            if ( !list_empty(&vmce->impact_header) )
            {
                entry = list_entry(vmce->impact_header.next,
                                   struct bank_entry, list);
                if ( entry->mci_status & MCi_STATUS_VAL )
                    mce_printk(MCE_QUIET, "MCE: MCi_STATUS MSR should have "
                               "been cleared before write MCG_STATUS MSR\n");

                mce_printk(MCE_QUIET, "MCE: Delete HVM last injection "
                           "Node, nr_injection %u\n",
                           vmce->nr_injection);
                list_del(&entry->list);
                xfree(entry);
            }
            else
                mce_printk(MCE_QUIET, "MCE: Not found HVM guest"
                           " last injection Node, something Wrong!\n");
        }
        break;
    case MSR_IA32_MCG_CAP:
        mce_printk(MCE_QUIET, "MCE: MCG_CAP is read-only\n");
        ret = -1;
        break;
    default:
        ret = mce_bank_msr(cur, msr) ? bank_mce_wrmsr(cur, msr, val) : 0;
        break;
    }

    spin_unlock(&vmce->lock);
    return ret;
}

static int vmce_save_vcpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    int err = 0;

    for_each_vcpu( d, v ) {
        struct hvm_vmce_vcpu ctxt = {
            .caps = v->arch.mcg_cap
        };

        err = hvm_save_entry(VMCE_VCPU, v->vcpu_id, h, &ctxt);
        if ( err )
            break;
    }

    return err;
}

static int vmce_load_vcpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    struct hvm_vmce_vcpu ctxt;
    int err;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        err = -EINVAL;
    }
    else
        err = hvm_load_entry(VMCE_VCPU, h, &ctxt);

    return err ?: vmce_restore_vcpu(v, ctxt.caps);
}

HVM_REGISTER_SAVE_RESTORE(VMCE_VCPU, vmce_save_vcpu_ctxt,
                          vmce_load_vcpu_ctxt, 1, HVMSR_PER_VCPU);

int inject_vmce(struct domain *d)
{
    int cpu = smp_processor_id();

    /* PV guest and HVM guest have different vMCE# injection methods. */
    if ( !test_and_set_bool(d->vcpu[0]->mce_pending) )
    {
        if ( d->is_hvm )
        {
            mce_printk(MCE_VERBOSE, "MCE: inject vMCE to HVM DOM %d\n",
                       d->domain_id);
            vcpu_kick(d->vcpu[0]);
        }
        else
        {
            mce_printk(MCE_VERBOSE, "MCE: inject vMCE to PV DOM%d\n",
                       d->domain_id);
            if ( guest_has_trap_callback(d, 0, TRAP_machine_check) )
            {
                cpumask_copy(d->vcpu[0]->cpu_affinity_tmp,
                             d->vcpu[0]->cpu_affinity);
                mce_printk(MCE_VERBOSE, "MCE: CPU%d set affinity, old %d\n",
                           cpu, d->vcpu[0]->processor);
                vcpu_set_affinity(d->vcpu[0], cpumask_of(cpu));
                vcpu_kick(d->vcpu[0]);
            }
            else
            {
                mce_printk(MCE_VERBOSE,
                           "MCE: Kill PV guest with No MCE handler\n");
                domain_crash(d);
            }
        }
    }
    else
    {
        /* new vMCE comes while first one has not been injected yet,
         * in this case, inject fail. [We can't lose this vMCE for
         * the mce node's consistency].
         */
        mce_printk(MCE_QUIET, "There's a pending vMCE waiting to be injected "
                   " to this DOM%d!\n", d->domain_id);
        return -1;
    }
    return 0;
}

/* This node list records errors impacting a domain. when one
 * MCE# happens, one error bank impacts a domain. This error node
 * will be inserted to the tail of the per_dom data for vMCE# MSR
 * virtualization. When one vMCE# injection is finished processing
 * processed by guest, the corresponding node will be deleted.
 * This node list is for GUEST vMCE# MSRS virtualization.
 */
static struct bank_entry* alloc_bank_entry(void)
{
    struct bank_entry *entry;

    entry = xzalloc(struct bank_entry);
    if ( entry == NULL )
    {
        printk(KERN_ERR "MCE: malloc bank_entry failed\n");
        return NULL;
    }

    INIT_LIST_HEAD(&entry->list);
    return entry;
}

/* Fill error bank info for #vMCE injection and GUEST vMCE#
 * MSR virtualization data
 * 1) Log down how many nr_injections of the impacted.
 * 2) Copy MCE# error bank to impacted DOM node list,
 *    for vMCE# MSRs virtualization
 */
int fill_vmsr_data(struct mcinfo_bank *mc_bank, struct domain *d,
                   uint64_t gstatus) {
    struct bank_entry *entry;

    /* This error bank impacts one domain, we need to fill domain related
     * data for vMCE MSRs virtualization and vMCE# injection */
    if ( mc_bank->mc_domid != (uint16_t)~0 )
    {
        /* For HVM guest, Only when first vMCE is consumed by HVM guest
         * successfully, will we generete another node and inject another vMCE.
         */
        if ( d->is_hvm && (dom_vmce(d)->nr_injection > 0) )
        {
            mce_printk(MCE_QUIET, "MCE: HVM guest has not handled previous"
                       " vMCE yet!\n");
            return -1;
        }

        entry = alloc_bank_entry();
        if ( entry == NULL )
            return -1;

        entry->mci_status = mc_bank->mc_status;
        entry->mci_addr = mc_bank->mc_addr;
        entry->mci_misc = mc_bank->mc_misc;
        entry->bank = mc_bank->mc_bank;

        spin_lock(&dom_vmce(d)->lock);
        /* New error Node, insert to the tail of the per_dom data */
        list_add_tail(&entry->list, &dom_vmce(d)->impact_header);
        /* Fill MSR global status */
        dom_vmce(d)->mcg_status = gstatus;
        /* New node impact the domain, need another vMCE# injection*/
        dom_vmce(d)->nr_injection++;
        spin_unlock(&dom_vmce(d)->lock);

        mce_printk(MCE_VERBOSE,"MCE: Found error @[BANK%d "
                   "status %"PRIx64" addr %"PRIx64" domid %d]\n ",
                   mc_bank->mc_bank, mc_bank->mc_status, mc_bank->mc_addr,
                   mc_bank->mc_domid);
    }

    return 0;
}

#if 0 /* currently unused */
int vmce_domain_inject(
    struct mcinfo_bank *bank, struct domain *d, struct mcinfo_global *global)
{
    int ret;

    ret = fill_vmsr_data(bank, d, global->mc_gstatus);
    if ( ret < 0 )
        return ret;

    return inject_vmce(d);
}
#endif

int vmce_init(struct cpuinfo_x86 *c)
{
    u64 value;
    unsigned int i;

    if ( !h_mci_ctrl )
    {
        h_mci_ctrl = xmalloc_array(uint64_t, nr_mce_banks);
        if (!h_mci_ctrl)
        {
            dprintk(XENLOG_INFO, "Failed to alloc h_mci_ctrl\n");
            return -ENOMEM;
        }
        /* Don't care banks before firstbank */
        memset(h_mci_ctrl, ~0,
               min(firstbank, nr_mce_banks) * sizeof(*h_mci_ctrl));
        for (i = firstbank; i < nr_mce_banks; i++)
            rdmsrl(MSR_IA32_MCx_CTL(i), h_mci_ctrl[i]);
    }

    rdmsrl(MSR_IA32_MCG_CAP, value);
    /* For Guest vMCE usage */
    g_mcg_cap = value & (MCG_CAP_COUNT | MCG_CTL_P | MCG_TES_P | MCG_SER_P);
    if (value & MCG_CTL_P)
        rdmsrl(MSR_IA32_MCG_CTL, h_mcg_ctl);

    return 0;
}

static int mca_ctl_conflict(struct mcinfo_bank *bank, struct domain *d)
{
    int bank_nr;

    if ( !bank || !d || !h_mci_ctrl )
        return 1;

    /* Will MCE happen in host if If host mcg_ctl is 0? */
    if ( ~d->arch.vmca_msrs->mcg_ctl & h_mcg_ctl )
        return 1;

    bank_nr = bank->mc_bank;
    if (~d->arch.vmca_msrs->mci_ctl[bank_nr] & h_mci_ctrl[bank_nr] )
        return 1;
    return 0;
}

static int is_hvm_vmce_ready(struct mcinfo_bank *bank, struct domain *d)
{
    struct vcpu *v;
    int no_vmce = 0, i;

    if (!is_hvm_domain(d))
        return 0;

    /* kill guest if not enabled vMCE */
    for_each_vcpu(d, v)
    {
        if (!(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_MCE))
        {
            no_vmce = 1;
            break;
        }

        if (!mce_broadcast)
            break;
    }

    if (no_vmce)
        return 0;

    /* Guest has virtualized family/model information */
    for ( i = 0; i < MAX_CPUID_INPUT; i++ )
    {
        if (d->arch.cpuids[i].input[0] == 0x1)
        {
            uint32_t veax = d->arch.cpuids[i].eax, vfam, vmod;

			vfam = (veax >> 8) & 15;
			vmod = (veax >> 4) & 15;

            if (vfam == 0x6 || vfam == 0xf)
                vmod += ((veax >> 16) & 0xF) << 4;
			if (vfam == 0xf)
				vfam += (veax >> 20) & 0xff;

            if ( ( vfam != boot_cpu_data.x86 ) ||
                 (vmod != boot_cpu_data.x86_model) )
            {
                dprintk(XENLOG_WARNING,
                    "No vmce for different virtual family/model cpuid\n");
                no_vmce = 1;
            }
            break;
        }
    }

    if (no_vmce)
        return 0;

    /* Guest has different MCE ctl value setting */
    if (mca_ctl_conflict(bank, d))
    {
        dprintk(XENLOG_WARNING,
          "No vmce, guest has different mca control setting\n");
        return 0;
    }

    return 1;
}

int is_vmce_ready(struct mcinfo_bank *bank, struct domain *d)
{
    if ( d == dom0)
        return dom0_vmce_enabled();

    /* No vMCE to HVM guest now */
    if ( is_hvm_domain(d) )
        return is_hvm_vmce_ready(bank, d);

    return 0;
}

/* It's said some ram is setup as mmio_direct for UC cache attribute */
#define P2M_UNMAP_TYPES (p2m_to_mask(p2m_ram_rw) \
                                | p2m_to_mask(p2m_ram_logdirty) \
                                | p2m_to_mask(p2m_ram_ro)       \
                                | p2m_to_mask(p2m_mmio_direct))

/*
 * Currently all CPUs are redenzevous at the MCE softirq handler, no
 * need to consider paging p2m type
 * Currently only support HVM guest with EPT paging mode
 * XXX following situation missed:
 * PoD, Foreign mapped, Granted, Shared
 */
int unmmap_broken_page(struct domain *d, mfn_t mfn, unsigned long gfn)
{
    mfn_t r_mfn;
    p2m_type_t pt;
    int rc;

    /* Always trust dom0's MCE handler will prevent future access */
    if ( d == dom0 )
        return 0;

    if (!mfn_valid(mfn_x(mfn)))
        return -EINVAL;

    if ( !is_hvm_domain(d) || !paging_mode_hap(d) )
        return -ENOSYS;

    rc = -1;
    r_mfn = get_gfn_query(d, gfn, &pt);
    if ( p2m_to_mask(pt) & P2M_UNMAP_TYPES)
    {
        ASSERT(mfn_x(r_mfn) == mfn_x(mfn));
        p2m_change_type(d, gfn, pt, p2m_ram_broken);
        rc = 0;
    }
    put_gfn(d, gfn);

    return rc;
}

