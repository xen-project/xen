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
#include <asm/processor.h>
#include <public/sysctl.h>
#include <asm/system.h>
#include <asm/msr.h>
#include <asm/p2m.h>
#include "mce.h"
#include "x86_mca.h"

int vmce_init_msr(struct domain *d)
{
    if ( dom_vmce(d) )
    {
        dprintk(XENLOG_G_WARNING, "Domain %d has inited vMCE\n", d->domain_id);
        return 0;
    }

    /* Allocate the vmca_msrs and mci_ctl togother */
    dom_vmce(d) = xmalloc(struct domain_mca_msrs);
    if ( !dom_vmce(d) )
        return -ENOMEM;

    dom_vmce(d)->mci_ctl = xmalloc_array(uint64_t, nr_mce_banks);
    if ( !dom_vmce(d)->mci_ctl )
    {
        xfree(dom_vmce(d));
        return -ENOMEM;
    }
    memset(d->arch.vmca_msrs->mci_ctl, ~0,
           sizeof(d->arch.vmca_msrs->mci_ctl));

    dom_vmce(d)->mcg_status = 0x0;
    dom_vmce(d)->mcg_cap = g_mcg_cap;
    dom_vmce(d)->mcg_ctl = ~(uint64_t)0x0;
    dom_vmce(d)->nr_injection = 0;

    INIT_LIST_HEAD(&d->arch.vmca_msrs->impact_header);
    spin_lock_init(&d->arch.vmca_msrs->lock);

    return 0;
}

/*
 * Caller should make sure msr is bank msr */
static int bank_mce_rdmsr(struct domain *d, uint32_t msr, uint64_t *val)
{
    int bank, ret = 1;
    struct domain_mca_msrs *vmce;
    struct bank_entry *entry = NULL;

    if (!d)
        return -EINVAL;
    vmce = dom_vmce(d);
    ASSERT(vmce);

    bank = (msr - MSR_IA32_MC0_CTL) / 4;
    if (bank >= nr_mce_banks)
        return -1;

    switch (msr & (MSR_IA32_MC0_CTL | 3))
    {
    case MSR_IA32_MC0_CTL:
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
            if (entry->bank == bank) {
                *val = entry->mci_status;
                mce_printk(MCE_VERBOSE,
                  "MCE: rd MC%u_STATUS in vMCE# context "
                  "value 0x%"PRIx64"\n", bank, *val);
            }
            else
                entry = NULL;
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
                ret = intel_mce_rdmsr(msr, val);
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
    struct domain *d = current->domain;
    struct domain_mca_msrs *vmce;
    int ret = 1;

    *val = 0;

    vmce = dom_vmce(d);
    if ( !vmce )
    {
        /* XXX more handle here */
        return 0;
    }

    spin_lock(&d->arch.vmca_msrs->lock);

    switch ( msr )
    {
    case MSR_IA32_MCG_STATUS:
        *val = vmce->mcg_status;
        if (*val)
            mce_printk(MCE_VERBOSE,
                "MCE: rdmsr MCG_STATUS 0x%"PRIx64"\n", *val);
        break;
    case MSR_IA32_MCG_CAP:
        *val = vmce->mcg_cap;
        mce_printk(MCE_VERBOSE, "MCE: rdmsr MCG_CAP 0x%"PRIx64"\n",
            *val);
        break;
    case MSR_IA32_MCG_CTL:
        /* Always 0 if no CTL support */
        *val = vmce->mcg_ctl & h_mcg_ctl;
        mce_printk(MCE_VERBOSE, "MCE: rdmsr MCG_CTL 0x%"PRIx64"\n",
            *val);
        break;
    default:
        if ( mce_bank_msr(msr) )
            ret = bank_mce_rdmsr(d, msr, val);
        else
            ret = 0;
        break;
    }

    spin_unlock(&d->arch.vmca_msrs->lock);
    return ret;
}

int bank_mce_wrmsr(struct domain *d, u32 msr, u64 val)
{
    int bank, ret = 1;
    struct domain_mca_msrs *vmce;
    struct bank_entry *entry = NULL;

    if (!d)
        return -EINVAL;
    vmce = dom_vmce(d);
    ASSERT(vmce && vmce->mci_ctl);

    bank = (msr - MSR_IA32_MC0_CTL) / 4;
    if (bank >= nr_mce_banks)
        return -EINVAL;

    switch ( msr & (MSR_IA32_MC0_CTL | 3) )
    {
    case MSR_IA32_MC0_CTL:
        vmce->mci_ctl[bank] = val;
            break;
    case MSR_IA32_MC0_STATUS:
            /* Give the first entry of the list, it corresponds to current
             * vMCE# injection. When vMCE# is finished processing by the
             * the guest, this node will be deleted.
             * Only error bank is written. Non-error banks simply return.
             */
            if ( !list_empty(&d->arch.vmca_msrs->impact_header) )
            {
                entry = list_entry(d->arch.vmca_msrs->impact_header.next,
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
            ret = intel_mce_wrmsr(msr, val);
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
    struct domain *d = current->domain;
    struct bank_entry *entry = NULL;
    struct domain_mca_msrs *vmce;
    int ret = 1;

    if ( !g_mcg_cap )
        return 0;

    vmce = dom_vmce(d);
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
        if ( d->is_hvm && (vmce->nr_injection > 0) )
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
        if ( mce_bank_msr(msr) )
            ret = bank_mce_wrmsr(d, msr, val);
        else
            ret = 0;
        break;
    }

    spin_unlock(&vmce->lock);
    return ret;
}

int inject_vmce(struct domain *d)
{
    int cpu = smp_processor_id();
    cpumask_t affinity;

    /* PV guest and HVM guest have different vMCE# injection
     * methods*/
    if ( !test_and_set_bool(d->vcpu[0]->mce_pending) )
    {
        if (d->is_hvm)
        {
            mce_printk(MCE_VERBOSE, "MCE: inject vMCE to HVM DOM %d\n",
                        d->domain_id);
            vcpu_kick(d->vcpu[0]);
        }
        /* PV guest including DOM0 */
        else
        {
            mce_printk(MCE_VERBOSE, "MCE: inject vMCE to PV DOM%d\n",
                        d->domain_id);
            if (guest_has_trap_callback
                   (d, 0, TRAP_machine_check))
            {
                d->vcpu[0]->cpu_affinity_tmp =
                        d->vcpu[0]->cpu_affinity;
                cpus_clear(affinity);
                cpu_set(cpu, affinity);
                mce_printk(MCE_VERBOSE, "MCE: CPU%d set affinity, old %d\n", cpu,
                            d->vcpu[0]->processor);
                vcpu_set_affinity(d->vcpu[0], &affinity);
                vcpu_kick(d->vcpu[0]);
            }
            else
            {
                mce_printk(MCE_VERBOSE, "MCE: Kill PV guest with No MCE handler\n");
                domain_crash(d);
            }
        }
    }
    else {
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
static struct bank_entry* alloc_bank_entry(void) {
    struct bank_entry *entry;

    entry = xmalloc(struct bank_entry);
    if (!entry) {
        printk(KERN_ERR "MCE: malloc bank_entry failed\n");
        return NULL;
    }
    memset(entry, 0x0, sizeof(entry));
    INIT_LIST_HEAD(&entry->list);
    return entry;
}

/* Fill error bank info for #vMCE injection and GUEST vMCE#
 * MSR virtualization data
 * 1) Log down how many nr_injections of the impacted.
 * 2) Copy MCE# error bank to impacted DOM node list,
      for vMCE# MSRs virtualization
*/

int fill_vmsr_data(struct mcinfo_bank *mc_bank, struct domain *d,
        uint64_t gstatus) {
    struct bank_entry *entry;

    /* This error bank impacts one domain, we need to fill domain related
     * data for vMCE MSRs virtualization and vMCE# injection */
    if (mc_bank->mc_domid != (uint16_t)~0) {
        /* For HVM guest, Only when first vMCE is consumed by HVM guest successfully,
         * will we generete another node and inject another vMCE
         */
        if ( (d->is_hvm) && (d->arch.vmca_msrs->nr_injection > 0) )
        {
            mce_printk(MCE_QUIET, "MCE: HVM guest has not handled previous"
                        " vMCE yet!\n");
            return -1;
        }
        entry = alloc_bank_entry();
        if (entry == NULL)
            return -1;

        entry->mci_status = mc_bank->mc_status;
        entry->mci_addr = mc_bank->mc_addr;
        entry->mci_misc = mc_bank->mc_misc;
        entry->bank = mc_bank->mc_bank;

        spin_lock(&d->arch.vmca_msrs->lock);
        /* New error Node, insert to the tail of the per_dom data */
        list_add_tail(&entry->list, &d->arch.vmca_msrs->impact_header);
        /* Fill MSR global status */
        d->arch.vmca_msrs->mcg_status = gstatus;
        /* New node impact the domain, need another vMCE# injection*/
        d->arch.vmca_msrs->nr_injection++;
        spin_unlock(&d->arch.vmca_msrs->lock);

        mce_printk(MCE_VERBOSE,"MCE: Found error @[BANK%d "
                "status %"PRIx64" addr %"PRIx64" domid %d]\n ",
                mc_bank->mc_bank, mc_bank->mc_status, mc_bank->mc_addr,
                mc_bank->mc_domid);
    }
    return 0;
}

int vmce_domain_inject(struct mcinfo_bank *bank, struct domain *d, struct mcinfo_global *global)
{
    int ret;

    ret = fill_vmsr_data(bank, d, global->mc_gstatus);
    if (ret < 0)
        return ret;

    return inject_vmce(d);
}

