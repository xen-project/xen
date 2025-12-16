/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/domain.h>
#include <xen/init.h>
#include <xen/sections.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/percpu.h>

#include <asm/atomic.h>
#include <asm/csr.h>
#include <asm/flushtlb.h>
#include <asm/p2m.h>

/* Xen command-line option to enable VMIDs */
static bool __ro_after_init opt_vmid = true;
boolean_param("vmid", opt_vmid);

/*
 * VMIDs partition the physical TLB. In the current implementation VMIDs are
 * introduced to reduce the number of TLB flushes. Each time a guest-physical
 * address space changes, instead of flushing the TLB, a new VMID is
 * assigned. This reduces the number of TLB flushes to at most 1/#VMIDs.
 * The biggest advantage is that hot parts of the hypervisor's code and data
 * retain in the TLB.
 *
 * Sketch of the Implementation:
 *
 * VMIDs are a hart-local resource.  As preemption of VMIDs is not possible,
 * VMIDs are assigned in a round-robin scheme. To minimize the overhead of
 * VMID invalidation, at the time of a TLB flush, VMIDs are tagged with a
 * 64-bit generation. Only on a generation overflow the code needs to
 * invalidate all VMID information stored at the VCPUs with are run on the
 * specific physical processor. When this overflow appears VMID usage is
 * disabled to retain correctness.
 */

/* Per-Hart VMID management. */
struct vmid_data {
   uint64_t generation;
   uint16_t next_vmid;
   uint16_t max_vmid;
   bool used;
};

static DEFINE_PER_CPU(struct vmid_data, vmid_data);

/*
 * vmidlen_detect() is expected to be called during secondary hart bring-up,
 * so it should not be marked as __init.
 */
static unsigned int vmidlen_detect(void)
{
    unsigned int vmid_bits;
    unsigned char gstage_mode = get_max_supported_mode();

    /*
     * According to the RISC-V Privileged Architecture Spec:
     *   When MODE=Bare, guest physical addresses are equal to supervisor
     *   physical addresses, and there is no further memory protection
     *   for a guest virtual machine beyond the physical memory protection
     *   scheme described in Section "Physical Memory Protection".
     *   In this case, the remaining fields in hgatp must be set to zeros.
     * Thereby it is necessary to set gstage_mode not equal to Bare.
     */
    ASSERT(gstage_mode != HGATP_MODE_OFF);
    csr_write(CSR_HGATP,
              MASK_INSR(gstage_mode, HGATP_MODE_MASK) | HGATP_VMID_MASK);
    vmid_bits = MASK_EXTR(csr_read(CSR_HGATP), HGATP_VMID_MASK);
    vmid_bits = flsl(vmid_bits);
    csr_write(CSR_HGATP, _AC(0, UL));

    /* local_hfence_gvma_all() will be called at the end of pre_gstage_init. */

    return vmid_bits;
}

/*
 * vmid_init() is expected to be called during secondary hart bring-up,
 * so it should not be marked as __init.
 */
void vmid_init(void)
{
    static int8_t __ro_after_init g_vmid_used = -1;

    unsigned int vmid_len = vmidlen_detect();
    struct vmid_data *data = &this_cpu(vmid_data);

    BUILD_BUG_ON(MASK_EXTR(HGATP_VMID_MASK, HGATP_VMID_MASK) >
                 (BIT((sizeof(data->max_vmid) * BITS_PER_BYTE), UL) - 1));

    data->max_vmid = BIT(vmid_len, U) - 1;
    data->used = opt_vmid && (vmid_len > 1);

    if ( g_vmid_used < 0 )
    {
        g_vmid_used = data->used;
        printk("VMIDs use is %sabled\n", data->used ? "en" : "dis");
    }
    else if ( g_vmid_used != data->used )
        printk("CPU%u: VMIDs use is %sabled\n", smp_processor_id(),
               data->used ? "en" : "dis");

    /* Zero indicates 'invalid generation', so we start the count at one. */
    data->generation = 1;

    /* Zero indicates 'VMIDs use disabled', so we start the count at one. */
    data->next_vmid = 1;
}

void vmid_flush_vcpu(struct vcpu *v)
{
    write_atomic(&v->arch.vmid.generation, 0);
}

void vmid_flush_hart(void)
{
    struct vmid_data *data = &this_cpu(vmid_data);

    if ( !data->used )
        return;

    if ( likely(++data->generation != 0) )
        return;

    /*
     * VMID generations are 64 bit.  Overflow of generations never happens.
     * For safety, we simply disable ASIDs, so correctness is established; it
     * only runs a bit slower.
     */
    printk("VMID generation overrun. Disabling VMIDs\n");
    data->used = false;
}

bool vmid_handle_vmenter(struct vcpu_vmid *vmid)
{
    struct vmid_data *data = &this_cpu(vmid_data);

    if ( !data->used )
        goto disabled;

    /* Test if VCPU has valid VMID. */
    if ( read_atomic(&vmid->generation) == data->generation )
        return 0;

    /* If there are no free VMIDs, need to go to a new generation. */
    if ( unlikely(data->next_vmid > data->max_vmid) )
    {
        vmid_flush_hart();
        data->next_vmid = 1;
        if ( !data->used )
            goto disabled;
    }

    /* Now guaranteed to be a free VMID. */
    vmid->vmid = data->next_vmid++;
    write_atomic(&vmid->generation, data->generation);

    /*
     * When we assign VMID 1, flush all TLB entries as we are starting a new
     * generation, and all old VMID allocations are now stale.
     */
    return vmid->vmid == 1;

 disabled:
    vmid->vmid = 0;
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
