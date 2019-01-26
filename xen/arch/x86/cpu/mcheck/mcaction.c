#include <xen/types.h>
#include <xen/sched.h>
#include "mcaction.h"
#include "vmce.h"
#include "mce.h"

static struct mcinfo_recovery *
mci_action_add_pageoffline(int bank, struct mc_info *mi,
                           mfn_t mfn, uint32_t status)
{
    struct mcinfo_recovery *rec;

    if ( !mi )
        return NULL;

    rec = x86_mcinfo_reserve(mi, sizeof(*rec), MC_TYPE_RECOVERY);
    if ( !rec )
    {
        mi->flags |= MCINFO_FLAGS_UNCOMPLETE;
        return NULL;
    }

    rec->mc_bank = bank;
    rec->action_types = MC_ACTION_PAGE_OFFLINE;
    rec->action_info.page_retire.mfn = mfn_x(mfn);
    rec->action_info.page_retire.status = status;
    return rec;
}

mce_check_addr_t mc_check_addr = NULL;

void mce_register_addrcheck(mce_check_addr_t cbfunc)
{
    mc_check_addr = cbfunc;
}

void
mc_memerr_dhandler(struct mca_binfo *binfo,
                   enum mce_result *result,
                   const struct cpu_user_regs *regs)
{
    struct mcinfo_bank *bank = binfo->mib;
    struct mcinfo_global *global = binfo->mig;
    struct domain *d;
    mfn_t mfn;
    unsigned long gfn;
    uint32_t status;
    int vmce_vcpuid;
    unsigned int mc_vcpuid;

    if ( !mc_check_addr(bank->mc_status, bank->mc_misc, MC_ADDR_PHYSICAL) )
    {
        dprintk(XENLOG_WARNING,
                "No physical address provided for memory error\n");
        return;
    }

    mfn = maddr_to_mfn(bank->mc_addr);
    if ( offline_page(mfn, 1, &status) )
    {
        dprintk(XENLOG_WARNING,
                "Failed to offline page %"PRI_mfn" for MCE error\n",
                mfn_x(mfn));
        return;
    }

    mci_action_add_pageoffline(binfo->bank, binfo->mi, mfn, status);

    /* This is free page */
    if ( status & PG_OFFLINE_OFFLINED )
        *result = MCER_RECOVERED;
    else if ( status & PG_OFFLINE_AGAIN )
        *result = MCER_CONTINUE;
    else if ( status & PG_OFFLINE_PENDING )
    {
        /* This page has owner */
        if ( status & PG_OFFLINE_OWNED )
        {
            bank->mc_domid = status >> PG_OFFLINE_OWNER_SHIFT;
            mce_printk(MCE_QUIET, "MCE: This error page is ownded"
                       " by DOM %d\n", bank->mc_domid);
            /*
             * XXX: Cannot handle shared pages yet
             * (this should identify all domains and gfn mapping to
             *  the mfn in question)
             */
            BUG_ON( bank->mc_domid == DOMID_COW );
            if ( bank->mc_domid != DOMID_XEN )
            {
                d = get_domain_by_id(bank->mc_domid);
                ASSERT(d);
                gfn = get_gpfn_from_mfn((bank->mc_addr) >> PAGE_SHIFT);

                if ( unmmap_broken_page(d, mfn, gfn) )
                {
                    printk("Unmap broken memory %"PRI_mfn" for DOM%d failed\n",
                           mfn_x(mfn), d->domain_id);
                    goto vmce_failed;
                }

                mc_vcpuid = global->mc_vcpuid;
                if ( mc_vcpuid == XEN_MC_VCPUID_INVALID ||
                     /*
                      * Because MC# may happen asynchronously with the actual
                      * operation that triggers the error, the domain ID as
                      * well as the vCPU ID collected in 'global' at MC# are
                      * not always precise. In that case, fallback to broadcast.
                      */
                     global->mc_domid != bank->mc_domid ||
                     (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
                      (!(global->mc_gstatus & MCG_STATUS_LMCE) ||
                       !(d->vcpu[mc_vcpuid]->arch.vmce.mcg_ext_ctl &
                         MCG_EXT_CTL_LMCE_EN))) )
                    vmce_vcpuid = VMCE_INJECT_BROADCAST;
                else
                    vmce_vcpuid = mc_vcpuid;

                bank->mc_addr = gfn << PAGE_SHIFT |
                                (bank->mc_addr & (PAGE_SIZE - 1));
                if ( fill_vmsr_data(bank, d, global->mc_gstatus, vmce_vcpuid) )
                {
                    mce_printk(MCE_QUIET, "Fill vMCE# data for DOM%d "
                               "failed\n", bank->mc_domid);
                    goto vmce_failed;
                }

                /* We will inject vMCE to DOMU */
                if ( inject_vmce(d, vmce_vcpuid) < 0 )
                {
                    mce_printk(MCE_QUIET, "inject vMCE to DOM%d"
                               " failed\n", d->domain_id);
                    goto vmce_failed;
                }

                /*
                 * Impacted domain go on with domain's recovery job
                 * if the domain has its own MCA handler.
                 * For xen, it has contained the error and finished
                 * its own recovery job.
                 */
                *result = MCER_RECOVERED;
                put_domain(d);

                return;
vmce_failed:
                put_domain(d);
                domain_crash(d);
            }
        }
    }
}
