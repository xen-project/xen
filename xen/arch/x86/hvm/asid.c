/*
 * asid.c: ASID management
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2009, Citrix Systems, Inc.
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
#include <asm/hvm/asid.h>

/*
 * ASIDs partition the physical TLB.  In the current implementation ASIDs are
 * introduced to reduce the number of TLB flushes.  Each time the guest's
 * virtual address space changes (e.g. due to an INVLPG, MOV-TO-{CR3, CR4}
 * operation), instead of flushing the TLB, a new ASID is assigned.  This
 * reduces the number of TLB flushes to at most 1/#ASIDs.  The biggest
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

/* Per-CPU ASID management. */
struct hvm_asid_data {
   u64 core_asid_generation;
   u32 next_asid;
   u32 max_asid;
   bool_t disabled;
   bool_t initialised;
};

static DEFINE_PER_CPU(struct hvm_asid_data, hvm_asid_data);

void hvm_asid_init(int nasids)
{
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    /*
     * If already initialised, we just bump the generation to force a TLB
     * flush. Resetting the generation could be dangerous, if VCPUs still
     * exist that reference earlier generations on this CPU.
     */
    if ( test_and_set_bool(data->initialised) )
        return hvm_asid_flush_core();

    data->max_asid = nasids - 1;
    data->disabled = (nasids <= 1);

    printk("HVM: ASIDs %s \n",
           (data->disabled ? "disabled." : "enabled."));

    /* Zero indicates 'invalid generation', so we start the count at one. */
    data->core_asid_generation = 1;

    /* Zero indicates 'ASIDs disabled', so we start the count at one. */
    data->next_asid = 1;
}

void hvm_asid_invalidate_asid(struct vcpu *v)
{
    v->arch.hvm_vcpu.asid_generation = 0;
}

void hvm_asid_flush_core(void)
{
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    if ( data->disabled )
        return;

    if ( likely(++data->core_asid_generation != 0) )
    {
        data->next_asid = 1;
        return;
    }

    /*
     * ASID generations are 64 bit.  Overflow of generations never happens.
     * For safety, we simply disable ASIDs, so correctness is established; it
     * only runs a bit slower.
     */
    printk("HVM: ASID generation overrun. Disabling ASIDs.\n");
    data->disabled = 1;
}

bool_t hvm_asid_handle_vmenter(void)
{
    struct vcpu *curr = current;
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    /* On erratum #170 systems we must flush the TLB. 
     * Generation overruns are taken here, too. */
    if ( data->disabled )
    {
        curr->arch.hvm_vcpu.asid = 0;
        return 0;
    }

    /* Test if VCPU has valid ASID. */
    if ( curr->arch.hvm_vcpu.asid_generation == data->core_asid_generation )
        return 0;

    /* If there are no free ASIDs, need to go to a new generation */
    if ( unlikely(data->next_asid > data->max_asid) )
        hvm_asid_flush_core();

    /* Now guaranteed to be a free ASID. */
    curr->arch.hvm_vcpu.asid = data->next_asid++;
    curr->arch.hvm_vcpu.asid_generation = data->core_asid_generation;

    /*
     * When we assign ASID 1, flush all TLB entries as we are starting a new
     * generation, and all old ASID allocations are now stale. 
     */
    return (curr->arch.hvm_vcpu.asid == 1);
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
