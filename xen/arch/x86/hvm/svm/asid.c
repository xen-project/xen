/*
 * asid.c: handling ASIDs in SVM.
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/perfc.h>
#include <asm/hvm/svm/asid.h>

/*
 * This is the interface to SVM's ASID management.  ASIDs partition the
 * physical TLB for SVM.  In the current implementation ASIDs are introduced
 * to reduce the number of TLB flushes.  Each time the guest's virtual
 * address space changes (e.g. due to an INVLPG, MOV-TO-{CR3, CR4} operation),
 * instead of flushing the TLB, a new ASID is assigned.  This reduces the
 * number of TLB flushes to at most 1/#ASIDs (currently 1/64).  The biggest
 * advantage is that hot parts of the hypervisor's code and data retain in
 * the TLB.
 *
 * Sketch of the Implementation:
 *
 * ASIDs are a CPU-local resource.  As preemption of ASIDs is not possible,
 * ASIDs are assigned in a round-robin scheme.  To minimize the overhead of
 * ASID invalidation, at the time of a TLB flush,  ASIDs are tagged with a
 * 64-bit generation.  Only on a generation overflow the code needs to
 * invalidate all ASID information stored at the VCPUs with are run on the
 * specific physical processor.  This overflow appears after about 2^80
 * host processor cycles, so we do not optimize this case, but simply disable
 * ASID useage to retain correctness.
 */

/* usable guest asids  [ 1 .. get_max_asid() ) */
#define SVM_ASID_FIRST_GUEST_ASID       1

#define SVM_ASID_FIRST_GENERATION       0

/* triggers the flush of all generations on all VCPUs */
#define SVM_ASID_LAST_GENERATION        (0xfffffffffffffffd)

/* triggers assignment of new ASID to a VCPU */
#define SVM_ASID_INVALID_GENERATION     (SVM_ASID_LAST_GENERATION + 1)

/* Per-CPU ASID management. */
struct svm_asid_data {
   u64 core_asid_generation;
   u32 next_asid;
   u32 max_asid;
   u32 erratum170:1;
};

static DEFINE_PER_CPU(struct svm_asid_data, svm_asid_data);

/*
 * Get handle to CPU-local ASID management data.
 */
static struct svm_asid_data *svm_asid_core_data(void)
{
    return &get_cpu_var(svm_asid_data);
}

/*
 * Init ASID management for the current physical CPU.
 */
void svm_asid_init(struct cpuinfo_x86 *c)
{
    int nasids;
    struct svm_asid_data *data = svm_asid_core_data();

    /* Find #ASID. */
    nasids = cpuid_ebx(0x8000000A);
    data->max_asid = nasids - 1;

    /* Check if we can use ASIDs. */
    data->erratum170 =
        !((c->x86 == 0x10) ||
          ((c->x86 == 0xf) && (c->x86_model >= 0x68) && (c->x86_mask >= 1)));

    printk("AMD SVM: ASIDs %s \n",
           (data->erratum170 ? "disabled." : "enabled."));

    /* Initialize ASID assigment. */
    if ( data->erratum170 )
    {
        /* On errata #170, VCPUs and phys processors should have same
          generation.  We set both to invalid. */
        data->core_asid_generation = SVM_ASID_INVALID_GENERATION;
    }
    else
    {
        data->core_asid_generation = SVM_ASID_FIRST_GENERATION;
    }

    /* ASIDs are assigned round-robin.  Start with the first. */
    data->next_asid = SVM_ASID_FIRST_GUEST_ASID;
}

/*
 * Force VCPU to fetch a new ASID.
 */
void svm_asid_init_vcpu(struct vcpu *v)
{
    struct svm_asid_data *data = svm_asid_core_data();

    /* Trigger asignment of a new ASID. */
    v->arch.hvm_svm.asid_generation = SVM_ASID_INVALID_GENERATION;

    /*
     * This erratum is bound to a physical processor.  The tlb_control
     * field is not changed by the processor.  We only set tlb_control
     * on VMCB creation and on a migration.
     */
    if ( data->erratum170 )
    {
        /* Flush TLB every VMRUN to handle Errata #170. */
        v->arch.hvm_svm.vmcb->tlb_control = 1;
        /* All guests use same ASID. */
        v->arch.hvm_svm.vmcb->guest_asid  = 1;
    }
    else
    {
        /* These fields are handled on VMRUN */
        v->arch.hvm_svm.vmcb->tlb_control = 0;
        v->arch.hvm_svm.vmcb->guest_asid  = 0;
    }
}

/*
 * Increase the Generation to make free ASIDs, and indirectly cause a 
 * TLB flush of all ASIDs on the next vmrun.
 */
void svm_asid_inc_generation(void)
{
    struct svm_asid_data *data = svm_asid_core_data();

    if ( likely(data->core_asid_generation < SVM_ASID_LAST_GENERATION) )
    {
        /* Move to the next generation.  We can't flush the TLB now
         * because you need to vmrun to do that, and current might not
         * be a HVM vcpu, but the first HVM vcpu that runs after this 
         * will pick up ASID 1 and flush the TLBs. */
        data->core_asid_generation++;
        data->next_asid = SVM_ASID_FIRST_GUEST_ASID;
        return;
    }

    /*
     * ASID generations are 64 bit.  Overflow of generations never happens.
     * For safety, we simply disable ASIDs and switch to erratum #170 mode on
     * this core (flushing TLB always). So correctness is established; it
     * only runs a bit slower.
     */
    if ( !data->erratum170 )
    {
        printk("AMD SVM: ASID generation overrun. Disabling ASIDs.\n");
        data->erratum170 = 1;
        data->core_asid_generation = SVM_ASID_INVALID_GENERATION;
    }
}

/*
 * Called directly before VMRUN.  Checks if the VCPU needs a new ASID,
 * assigns it, and if required, issues required TLB flushes.
 */
asmlinkage void svm_asid_handle_vmrun(void)
{
    struct vcpu *v = current;
    struct svm_asid_data *data = svm_asid_core_data();

    /* On erratum #170 systems we must flush the TLB. 
     * Generation overruns are taken here, too. */
    if ( data->erratum170 )
    {
        v->arch.hvm_svm.vmcb->guest_asid  = 1;
        v->arch.hvm_svm.vmcb->tlb_control = 1;
        return;
    }

    /* Test if VCPU has valid ASID. */
    if ( likely(v->arch.hvm_svm.asid_generation ==
                data->core_asid_generation) )
    {
        /* May revert previous TLB-flush command. */
        v->arch.hvm_svm.vmcb->tlb_control = 0;
        return;
    }

    /* If there are no free ASIDs, need to go to a new generation */
    if ( unlikely(data->next_asid > data->max_asid) )
        svm_asid_inc_generation();

    /* Now guaranteed to be a free ASID. */
    v->arch.hvm_svm.vmcb->guest_asid = data->next_asid++;
    v->arch.hvm_svm.asid_generation  = data->core_asid_generation;

    /* When we assign ASID 1, flush all TLB entries.  We need to do it 
     * here because svm_asid_inc_generation() can be called at any time, 
     * but the TLB flush can only happen on vmrun. */
    if ( v->arch.hvm_svm.vmcb->guest_asid == SVM_ASID_FIRST_GUEST_ASID )
        v->arch.hvm_svm.vmcb->tlb_control = 1;
    else
        v->arch.hvm_svm.vmcb->tlb_control = 0;
}

void svm_asid_inv_asid(struct vcpu *v)
{
    v->arch.hvm_svm.asid_generation = SVM_ASID_INVALID_GENERATION;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
