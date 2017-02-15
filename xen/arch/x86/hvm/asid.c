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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/percpu.h>
#include <asm/hvm/asid.h>

/* Xen command-line option to enable ASIDs */
static int opt_asid_enabled = 1;
boolean_param("asid", opt_asid_enabled);

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
   uint64_t core_asid_generation;
   uint32_t next_asid;
   uint32_t max_asid;
   bool_t disabled;
};

static DEFINE_PER_CPU(struct hvm_asid_data, hvm_asid_data);

void hvm_asid_init(int nasids)
{
    static int8_t g_disabled = -1;
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    data->max_asid = nasids - 1;
    data->disabled = !opt_asid_enabled || (nasids <= 1);

    if ( g_disabled != data->disabled )
    {
        printk("HVM: ASIDs %sabled.\n", data->disabled ? "dis" : "en");
        if ( g_disabled < 0 )
            g_disabled = data->disabled;
    }

    /* Zero indicates 'invalid generation', so we start the count at one. */
    data->core_asid_generation = 1;

    /* Zero indicates 'ASIDs disabled', so we start the count at one. */
    data->next_asid = 1;
}

void hvm_asid_flush_vcpu_asid(struct hvm_vcpu_asid *asid)
{
    asid->generation = 0;
}

void hvm_asid_flush_vcpu(struct vcpu *v)
{
    hvm_asid_flush_vcpu_asid(&v->arch.hvm_vcpu.n1asid);
    hvm_asid_flush_vcpu_asid(&vcpu_nestedhvm(v).nv_n2asid);
}

void hvm_asid_flush_core(void)
{
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    if ( data->disabled )
        return;

    if ( likely(++data->core_asid_generation != 0) )
        return;

    /*
     * ASID generations are 64 bit.  Overflow of generations never happens.
     * For safety, we simply disable ASIDs, so correctness is established; it
     * only runs a bit slower.
     */
    printk("HVM: ASID generation overrun. Disabling ASIDs.\n");
    data->disabled = 1;
}

bool_t hvm_asid_handle_vmenter(struct hvm_vcpu_asid *asid)
{
    struct hvm_asid_data *data = &this_cpu(hvm_asid_data);

    /* On erratum #170 systems we must flush the TLB. 
     * Generation overruns are taken here, too. */
    if ( data->disabled )
        goto disabled;

    /* Test if VCPU has valid ASID. */
    if ( asid->generation == data->core_asid_generation )
        return 0;

    /* If there are no free ASIDs, need to go to a new generation */
    if ( unlikely(data->next_asid > data->max_asid) )
    {
        hvm_asid_flush_core();
        data->next_asid = 1;
        if ( data->disabled )
            goto disabled;
    }

    /* Now guaranteed to be a free ASID. */
    asid->asid = data->next_asid++;
    asid->generation = data->core_asid_generation;

    /*
     * When we assign ASID 1, flush all TLB entries as we are starting a new
     * generation, and all old ASID allocations are now stale. 
     */
    return (asid->asid == 1);

 disabled:
    asid->asid = 0;
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
