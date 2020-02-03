/**************************************************************************
 * viridian.c
 *
 * An implementation of some Viridian enlightenments. See Microsoft's
 * Hypervisor Top Level Functional Specification for more information.
 */

#include <xen/sched.h>
#include <xen/version.h>
#include <xen/hypercall.h>
#include <xen/domain_page.h>
#include <xen/param.h>
#include <asm/guest_access.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/apic.h>
#include <asm/hvm/support.h>
#include <public/sched.h>
#include <public/hvm/hvm_op.h>

#include "private.h"

/* Viridian Partition Privilege Flags */
typedef struct {
    /* Access to virtual MSRs */
    uint64_t AccessVpRunTimeReg:1;
    uint64_t AccessPartitionReferenceCounter:1;
    uint64_t AccessSynicRegs:1;
    uint64_t AccessSyntheticTimerRegs:1;
    uint64_t AccessIntrCtrlRegs:1;
    uint64_t AccessHypercallMsrs:1;
    uint64_t AccessVpIndex:1;
    uint64_t AccessResetReg:1;
    uint64_t AccessStatsReg:1;
    uint64_t AccessPartitionReferenceTsc:1;
    uint64_t AccessGuestIdleReg:1;
    uint64_t AccessFrequencyRegs:1;
    uint64_t AccessDebugRegs:1;
    uint64_t Reserved1:19;

    /* Access to hypercalls */
    uint64_t CreatePartitions:1;
    uint64_t AccessPartitionId:1;
    uint64_t AccessMemoryPool:1;
    uint64_t AdjustMessageBuffers:1;
    uint64_t PostMessages:1;
    uint64_t SignalEvents:1;
    uint64_t CreatePort:1;
    uint64_t ConnectPort:1;
    uint64_t AccessStats:1;
    uint64_t Reserved2:2;
    uint64_t Debugging:1;
    uint64_t CpuManagement:1;
    uint64_t Reserved3:1;
    uint64_t Reserved4:1;
    uint64_t Reserved5:1;
    uint64_t AccessVSM:1;
    uint64_t AccessVpRegisters:1;
    uint64_t Reserved6:1;
    uint64_t Reserved7:1;
    uint64_t EnableExtendedHypercalls:1;
    uint64_t StartVirtualProcessor:1;
    uint64_t Reserved8:10;
} HV_PARTITION_PRIVILEGE_MASK;

typedef union _HV_CRASH_CTL_REG_CONTENTS
{
    uint64_t AsUINT64;
    struct
    {
        uint64_t Reserved:63;
        uint64_t CrashNotify:1;
    } u;
} HV_CRASH_CTL_REG_CONTENTS;

/* Viridian CPUID leaf 3, Hypervisor Feature Indication */
#define CPUID3D_CRASH_MSRS (1 << 10)
#define CPUID3D_SINT_POLLING (1 << 17)

/* Viridian CPUID leaf 4: Implementation Recommendations. */
#define CPUID4A_HCALL_REMOTE_TLB_FLUSH (1 << 2)
#define CPUID4A_MSR_BASED_APIC         (1 << 3)
#define CPUID4A_RELAX_TIMER_INT        (1 << 5)
#define CPUID4A_SYNTHETIC_CLUSTER_IPI  (1 << 10)

/* Viridian CPUID leaf 6: Implementation HW features detected and in use */
#define CPUID6A_APIC_OVERLAY    (1 << 0)
#define CPUID6A_MSR_BITMAPS     (1 << 1)
#define CPUID6A_NESTED_PAGING   (1 << 3)

/*
 * Version and build number reported by CPUID leaf 2
 *
 * These numbers are chosen to match the version numbers reported by
 * Windows Server 2008.
 */
static uint16_t __read_mostly viridian_major = 6;
static uint16_t __read_mostly viridian_minor = 0;
static uint32_t __read_mostly viridian_build = 0x1772;

/*
 * Maximum number of retries before the guest will notify of failure
 * to acquire a spinlock.
 */
static uint32_t __read_mostly viridian_spinlock_retry_count = 2047;
integer_param("viridian-spinlock-retry-count",
              viridian_spinlock_retry_count);

void cpuid_viridian_leaves(const struct vcpu *v, uint32_t leaf,
                           uint32_t subleaf, struct cpuid_leaf *res)
{
    const struct domain *d = v->domain;
    const struct viridian_domain *vd = d->arch.hvm.viridian;

    ASSERT(is_viridian_domain(d));
    ASSERT(leaf >= 0x40000000 && leaf < 0x40000100);

    leaf -= 0x40000000;

    switch ( leaf )
    {
    case 0:
        res->a = 0x40000006; /* Maximum leaf */
        memcpy(&res->b, "Micr", 4);
        memcpy(&res->c, "osof", 4);
        memcpy(&res->d, "t Hv", 4);
        break;

    case 1:
        memcpy(&res->a, "Hv#1", 4);
        break;

    case 2:
        /*
         * Hypervisor information, but only if the guest has set its
         * own version number.
         */
        if ( vd->guest_os_id.raw == 0 )
            break;
        res->a = viridian_build;
        res->b = ((uint32_t)viridian_major << 16) | viridian_minor;
        res->c = 0; /* SP */
        res->d = 0; /* Service branch and number */
        break;

    case 3:
    {
        /*
         * The specification states that EAX and EBX are defined to be
         * the low and high parts of the partition privilege mask
         * respectively.
         */
        HV_PARTITION_PRIVILEGE_MASK mask = {
            .AccessIntrCtrlRegs = 1,
            .AccessHypercallMsrs = 1,
            .AccessVpIndex = 1,
        };
        union {
            HV_PARTITION_PRIVILEGE_MASK mask;
            struct { uint32_t lo, hi; };
        } u;

        if ( !(viridian_feature_mask(d) & HVMPV_no_freq) )
            mask.AccessFrequencyRegs = 1;
        if ( viridian_feature_mask(d) & HVMPV_time_ref_count )
            mask.AccessPartitionReferenceCounter = 1;
        if ( viridian_feature_mask(d) & HVMPV_reference_tsc )
            mask.AccessPartitionReferenceTsc = 1;
        if ( viridian_feature_mask(d) & HVMPV_synic )
            mask.AccessSynicRegs = 1;
        if ( viridian_feature_mask(d) & HVMPV_stimer )
            mask.AccessSyntheticTimerRegs = 1;

        u.mask = mask;

        res->a = u.lo;
        res->b = u.hi;

        if ( viridian_feature_mask(d) & HVMPV_crash_ctl )
            res->d = CPUID3D_CRASH_MSRS;
        if ( viridian_feature_mask(d) & HVMPV_synic )
            res->d |= CPUID3D_SINT_POLLING;

        break;
    }

    case 4:
        /* Recommended hypercall usage. */
        if ( vd->guest_os_id.raw == 0 || vd->guest_os_id.os < 4 )
            break;
        res->a = CPUID4A_RELAX_TIMER_INT;
        if ( viridian_feature_mask(d) & HVMPV_hcall_remote_tlb_flush )
            res->a |= CPUID4A_HCALL_REMOTE_TLB_FLUSH;
        if ( !cpu_has_vmx_apic_reg_virt )
            res->a |= CPUID4A_MSR_BASED_APIC;
        if ( viridian_feature_mask(d) & HVMPV_hcall_ipi )
            res->a |= CPUID4A_SYNTHETIC_CLUSTER_IPI;

        /*
         * This value is the recommended number of attempts to try to
         * acquire a spinlock before notifying the hypervisor via the
         * HVCALL_NOTIFY_LONG_SPIN_WAIT hypercall.
         */
        res->b = viridian_spinlock_retry_count;
        break;

    case 6:
        /* Detected and in use hardware features. */
        if ( cpu_has_vmx_virtualize_apic_accesses )
            res->a |= CPUID6A_APIC_OVERLAY;
        if ( cpu_has_vmx_msr_bitmap || (read_efer() & EFER_SVME) )
            res->a |= CPUID6A_MSR_BITMAPS;
        if ( hap_enabled(d) )
            res->a |= CPUID6A_NESTED_PAGING;
        break;
    }
}

static void dump_guest_os_id(const struct domain *d)
{
    const union hv_guest_os_id *goi;

    goi = &d->arch.hvm.viridian->guest_os_id;

    printk(XENLOG_G_INFO
           "d%d: VIRIDIAN GUEST_OS_ID: vendor: %x os: %x major: %x minor: %x sp: %x build: %x\n",
           d->domain_id, goi->vendor, goi->os, goi->major, goi->minor,
           goi->service_pack, goi->build_number);
}

static void dump_hypercall(const struct domain *d)
{
    const union viridian_page_msr *hg;

    hg = &d->arch.hvm.viridian->hypercall_gpa;

    printk(XENLOG_G_INFO "d%d: VIRIDIAN HYPERCALL: enabled: %x pfn: %lx\n",
           d->domain_id,
           hg->enabled, (unsigned long)hg->pfn);
}

static void enable_hypercall_page(struct domain *d)
{
    unsigned long gmfn = d->arch.hvm.viridian->hypercall_gpa.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    uint8_t *p;

    if ( !page || !get_page_type(page, PGT_writable_page) )
    {
        if ( page )
            put_page(page);
        gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n",
                 gmfn, mfn_x(page ? page_to_mfn(page) : INVALID_MFN));
        return;
    }

    p = __map_domain_page(page);

    /*
     * We set the bit 31 in %eax (reserved field in the Viridian hypercall
     * calling convention) to differentiate Xen and Viridian hypercalls.
     */
    *(u8  *)(p + 0) = 0x0d; /* orl $0x80000000, %eax */
    *(u32 *)(p + 1) = 0x80000000;
    *(u8  *)(p + 5) = 0x0f; /* vmcall/vmmcall */
    *(u8  *)(p + 6) = 0x01;
    *(u8  *)(p + 7) = (cpu_has_vmx ? 0xc1 : 0xd9);
    *(u8  *)(p + 8) = 0xc3; /* ret */
    memset(p + 9, 0xcc, PAGE_SIZE - 9); /* int3, int3, ... */

    unmap_domain_page(p);

    put_page_and_type(page);
}

int guest_wrmsr_viridian(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct viridian_vcpu *vv = v->arch.hvm.viridian;
    struct domain *d = v->domain;
    struct viridian_domain *vd = d->arch.hvm.viridian;

    ASSERT(is_viridian_domain(d));

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        vd->guest_os_id.raw = val;
        dump_guest_os_id(d);
        break;

    case HV_X64_MSR_HYPERCALL:
        vd->hypercall_gpa.raw = val;
        dump_hypercall(d);
        if ( vd->hypercall_gpa.enabled )
            enable_hypercall_page(d);
        break;

    case HV_X64_MSR_VP_INDEX:
        break;

    case HV_X64_MSR_EOI:
    case HV_X64_MSR_ICR:
    case HV_X64_MSR_TPR:
    case HV_X64_MSR_VP_ASSIST_PAGE:
    case HV_X64_MSR_SCONTROL:
    case HV_X64_MSR_SVERSION:
    case HV_X64_MSR_SIEFP:
    case HV_X64_MSR_SIMP:
    case HV_X64_MSR_EOM:
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
        return viridian_synic_wrmsr(v, idx, val);

    case HV_X64_MSR_TSC_FREQUENCY:
    case HV_X64_MSR_APIC_FREQUENCY:
    case HV_X64_MSR_REFERENCE_TSC:
    case HV_X64_MSR_TIME_REF_COUNT:
    case HV_X64_MSR_STIMER0_CONFIG ... HV_X64_MSR_STIMER3_COUNT:
        return viridian_time_wrmsr(v, idx, val);

    case HV_X64_MSR_CRASH_P0:
    case HV_X64_MSR_CRASH_P1:
    case HV_X64_MSR_CRASH_P2:
    case HV_X64_MSR_CRASH_P3:
    case HV_X64_MSR_CRASH_P4:
        BUILD_BUG_ON(HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 >=
                     ARRAY_SIZE(vv->crash_param));

        idx -= HV_X64_MSR_CRASH_P0;
        vv->crash_param[idx] = val;
        break;

    case HV_X64_MSR_CRASH_CTL:
    {
        HV_CRASH_CTL_REG_CONTENTS ctl;

        ctl.AsUINT64 = val;

        if ( !ctl.u.CrashNotify )
            break;

        spin_lock(&d->shutdown_lock);
        d->shutdown_code = SHUTDOWN_crash;
        spin_unlock(&d->shutdown_lock);

        gprintk(XENLOG_WARNING, "VIRIDIAN CRASH: %lx %lx %lx %lx %lx\n",
                vv->crash_param[0], vv->crash_param[1], vv->crash_param[2],
                vv->crash_param[3], vv->crash_param[4]);
        break;
    }

    default:
        gdprintk(XENLOG_INFO,
                 "Write %016"PRIx64" to unimplemented MSR %#x\n", val,
                 idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int guest_rdmsr_viridian(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    const struct viridian_vcpu *vv = v->arch.hvm.viridian;
    const struct domain *d = v->domain;
    const struct viridian_domain *vd = d->arch.hvm.viridian;

    ASSERT(is_viridian_domain(d));

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        *val = vd->guest_os_id.raw;
        break;

    case HV_X64_MSR_HYPERCALL:
        *val = vd->hypercall_gpa.raw;
        break;

    case HV_X64_MSR_VP_INDEX:
        *val = v->vcpu_id;
        break;

    case HV_X64_MSR_EOI:
    case HV_X64_MSR_ICR:
    case HV_X64_MSR_TPR:
    case HV_X64_MSR_VP_ASSIST_PAGE:
    case HV_X64_MSR_SCONTROL:
    case HV_X64_MSR_SVERSION:
    case HV_X64_MSR_SIEFP:
    case HV_X64_MSR_SIMP:
    case HV_X64_MSR_EOM:
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
        return viridian_synic_rdmsr(v, idx, val);

    case HV_X64_MSR_TSC_FREQUENCY:
    case HV_X64_MSR_APIC_FREQUENCY:
    case HV_X64_MSR_REFERENCE_TSC:
    case HV_X64_MSR_TIME_REF_COUNT:
    case HV_X64_MSR_STIMER0_CONFIG ... HV_X64_MSR_STIMER3_COUNT:
        return viridian_time_rdmsr(v, idx, val);

    case HV_X64_MSR_CRASH_P0:
    case HV_X64_MSR_CRASH_P1:
    case HV_X64_MSR_CRASH_P2:
    case HV_X64_MSR_CRASH_P3:
    case HV_X64_MSR_CRASH_P4:
        BUILD_BUG_ON(HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 >=
                     ARRAY_SIZE(vv->crash_param));

        idx -= HV_X64_MSR_CRASH_P0;
        *val = vv->crash_param[idx];
        break;

    case HV_X64_MSR_CRASH_CTL:
    {
        HV_CRASH_CTL_REG_CONTENTS ctl = {
            .u.CrashNotify = 1,
        };

        *val = ctl.AsUINT64;
        break;
    }

    default:
        gdprintk(XENLOG_INFO, "Read from unimplemented MSR %#x\n", idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_vcpu_init(struct vcpu *v)
{
    int rc;

    ASSERT(!v->arch.hvm.viridian);
    v->arch.hvm.viridian = xzalloc(struct viridian_vcpu);
    if ( !v->arch.hvm.viridian )
        return -ENOMEM;

    rc = viridian_synic_vcpu_init(v);
    if ( rc )
        goto fail;

    rc = viridian_time_vcpu_init(v);
    if ( rc )
        goto fail;

    return 0;

 fail:
    viridian_vcpu_deinit(v);

    return rc;
}

int viridian_domain_init(struct domain *d)
{
    int rc;

    ASSERT(!d->arch.hvm.viridian);
    d->arch.hvm.viridian = xzalloc(struct viridian_domain);
    if ( !d->arch.hvm.viridian )
        return -ENOMEM;

    rc = viridian_synic_domain_init(d);
    if ( rc )
        goto fail;

    rc = viridian_time_domain_init(d);
    if ( rc )
        goto fail;

    return 0;

 fail:
    viridian_domain_deinit(d);

    return rc;
}

void viridian_vcpu_deinit(struct vcpu *v)
{
    if ( !v->arch.hvm.viridian )
        return;

    viridian_time_vcpu_deinit(v);
    viridian_synic_vcpu_deinit(v);

    XFREE(v->arch.hvm.viridian);
}

void viridian_domain_deinit(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        viridian_vcpu_deinit(v);

    if ( !d->arch.hvm.viridian )
        return;

    viridian_time_domain_deinit(d);
    viridian_synic_domain_deinit(d);

    XFREE(d->arch.hvm.viridian);
}

/*
 * Windows should not issue the hypercalls requiring this callback in the
 * case where vcpu_id would exceed the size of the mask.
 */
static bool need_flush(void *ctxt, struct vcpu *v)
{
    uint64_t vcpu_mask = *(uint64_t *)ctxt;

    return vcpu_mask & (1ul << v->vcpu_id);
}

int viridian_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    int mode = hvm_guest_x86_mode(curr);
    unsigned long input_params_gpa, output_params_gpa;
    uint16_t status = HV_STATUS_SUCCESS;

    union hypercall_input {
        uint64_t raw;
        struct {
            uint16_t call_code;
            uint16_t fast:1;
            uint16_t rsvd1:15;
            uint16_t rep_count:12;
            uint16_t rsvd2:4;
            uint16_t rep_start:12;
            uint16_t rsvd3:4;
        };
    } input;

    union hypercall_output {
        uint64_t raw;
        struct {
            uint16_t result;
            uint16_t rsvd1;
            uint32_t rep_complete:12;
            uint32_t rsvd2:20;
        };
    } output = { 0 };

    ASSERT(is_viridian_domain(currd));

    switch ( mode )
    {
    case 8:
        input.raw = regs->rcx;
        input_params_gpa = regs->rdx;
        output_params_gpa = regs->r8;
        break;
    case 4:
        input.raw = (regs->rdx << 32) | regs->eax;
        input_params_gpa = (regs->rbx << 32) | regs->ecx;
        output_params_gpa = (regs->rdi << 32) | regs->esi;
        break;
    default:
        goto out;
    }

    switch ( input.call_code )
    {
    case HVCALL_NOTIFY_LONG_SPIN_WAIT:
        /*
         * See section 14.5.1 of the specification.
         */
        do_sched_op(SCHEDOP_yield, guest_handle_from_ptr(NULL, void));
        status = HV_STATUS_SUCCESS;
        break;

    case HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE:
    case HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST:
    {
        struct {
            uint64_t address_space;
            uint64_t flags;
            uint64_t vcpu_mask;
        } input_params;

        /* These hypercalls should never use the fast-call convention. */
        status = HV_STATUS_INVALID_PARAMETER;
        if ( input.fast )
            break;

        /* Get input parameters. */
        if ( hvm_copy_from_guest_phys(&input_params, input_params_gpa,
                                      sizeof(input_params)) !=
             HVMTRANS_okay )
            break;

        /*
         * It is not clear from the spec. if we are supposed to
         * include current virtual CPU in the set or not in this case,
         * so err on the safe side.
         */
        if ( input_params.flags & HV_FLUSH_ALL_PROCESSORS )
            input_params.vcpu_mask = ~0ul;

        /*
         * A false return means that another vcpu is currently trying
         * a similar operation, so back off.
         */
        if ( !hvm_flush_vcpu_tlb(need_flush, &input_params.vcpu_mask) )
            return HVM_HCALL_preempted;

        output.rep_complete = input.rep_count;

        status = HV_STATUS_SUCCESS;
        break;
    }

    case HVCALL_SEND_IPI:
    {
        struct vcpu *v;
        uint32_t vector;
        uint64_t vcpu_mask;

        status = HV_STATUS_INVALID_PARAMETER;

        /* Get input parameters. */
        if ( input.fast )
        {
            if ( input_params_gpa >> 32 )
                break;

            vector = input_params_gpa;
            vcpu_mask = output_params_gpa;
        }
        else
        {
            struct {
                uint32_t vector;
                uint8_t target_vtl;
                uint8_t reserved_zero[3];
                uint64_t vcpu_mask;
            } input_params;

            if ( hvm_copy_from_guest_phys(&input_params, input_params_gpa,
                                          sizeof(input_params)) !=
                 HVMTRANS_okay )
                break;

            if ( input_params.target_vtl ||
                 input_params.reserved_zero[0] ||
                 input_params.reserved_zero[1] ||
                 input_params.reserved_zero[2] )
                break;

            vector = input_params.vector;
            vcpu_mask = input_params.vcpu_mask;
        }

        if ( vector < 0x10 || vector > 0xff )
            break;

        for_each_vcpu ( currd, v )
        {
            if ( v->vcpu_id >= (sizeof(vcpu_mask) * 8) )
                break;

            if ( !(vcpu_mask & (1ul << v->vcpu_id)) )
                continue;

            vlapic_set_irq(vcpu_vlapic(v), vector, 0);
        }

        status = HV_STATUS_SUCCESS;
        break;
    }

    default:
        gprintk(XENLOG_WARNING, "unimplemented hypercall %04x\n",
                input.call_code);
        /* Fallthrough. */
    case HVCALL_EXT_CALL_QUERY_CAPABILITIES:
        /*
         * This hypercall seems to be erroneously issued by Windows
         * despite EnableExtendedHypercalls not being set in CPUID leaf 2.
         * Given that return a status of 'invalid code' has not so far
         * caused any problems it's not worth logging.
         */
        status = HV_STATUS_INVALID_HYPERCALL_CODE;
        break;
    }

out:
    output.result = status;
    switch (mode) {
    case 8:
        regs->rax = output.raw;
        break;
    default:
        regs->rdx = output.raw >> 32;
        regs->rax = (uint32_t)output.raw;
        break;
    }

    return HVM_HCALL_completed;
}

void viridian_dump_guest_page(const struct vcpu *v, const char *name,
                              const struct viridian_page *vp)
{
    if ( !vp->msr.enabled )
        return;

    printk(XENLOG_G_INFO "%pv: VIRIDIAN %s: pfn: %lx\n",
           v, name, (unsigned long)vp->msr.pfn);
}

void viridian_map_guest_page(struct domain *d, struct viridian_page *vp)
{
    unsigned long gmfn = vp->msr.pfn;
    struct page_info *page;

    if ( vp->ptr )
        return;

    page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    if ( !page )
        goto fail;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        goto fail;
    }

    vp->ptr = __map_domain_page_global(page);
    if ( !vp->ptr )
    {
        put_page_and_type(page);
        goto fail;
    }

    clear_page(vp->ptr);
    return;

 fail:
    gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n",
             gmfn, mfn_x(page ? page_to_mfn(page) : INVALID_MFN));
}

void viridian_unmap_guest_page(struct viridian_page *vp)
{
    struct page_info *page;

    if ( !vp->ptr )
        return;

    page = mfn_to_page(domain_page_map_to_mfn(vp->ptr));

    unmap_domain_page_global(vp->ptr);
    vp->ptr = NULL;

    put_page_and_type(page);
}

static int viridian_save_domain_ctxt(struct vcpu *v,
                                     hvm_domain_context_t *h)
{
    const struct domain *d = v->domain;
    const struct viridian_domain *vd = d->arch.hvm.viridian;
    struct hvm_viridian_domain_context ctxt = {
        .hypercall_gpa = vd->hypercall_gpa.raw,
        .guest_os_id = vd->guest_os_id.raw,
    };

    if ( !is_viridian_domain(d) )
        return 0;

    viridian_time_save_domain_ctxt(d, &ctxt);
    viridian_synic_save_domain_ctxt(d, &ctxt);

    return (hvm_save_entry(VIRIDIAN_DOMAIN, 0, h, &ctxt) != 0);
}

static int viridian_load_domain_ctxt(struct domain *d,
                                     hvm_domain_context_t *h)
{
    struct viridian_domain *vd = d->arch.hvm.viridian;
    struct hvm_viridian_domain_context ctxt;

    if ( hvm_load_entry_zeroextend(VIRIDIAN_DOMAIN, h, &ctxt) != 0 )
        return -EINVAL;

    vd->hypercall_gpa.raw = ctxt.hypercall_gpa;
    vd->guest_os_id.raw = ctxt.guest_os_id;

    viridian_synic_load_domain_ctxt(d, &ctxt);
    viridian_time_load_domain_ctxt(d, &ctxt);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VIRIDIAN_DOMAIN, viridian_save_domain_ctxt,
                          viridian_load_domain_ctxt, 1, HVMSR_PER_DOM);

static int viridian_save_vcpu_ctxt(struct vcpu *v, hvm_domain_context_t *h)
{
    struct hvm_viridian_vcpu_context ctxt = {};

    if ( !is_viridian_vcpu(v) )
        return 0;

    viridian_time_save_vcpu_ctxt(v, &ctxt);
    viridian_synic_save_vcpu_ctxt(v, &ctxt);

    return hvm_save_entry(VIRIDIAN_VCPU, v->vcpu_id, h, &ctxt);
}

static int viridian_load_vcpu_ctxt(struct domain *d,
                                   hvm_domain_context_t *h)
{
    unsigned int vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    struct hvm_viridian_vcpu_context ctxt;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry_zeroextend(VIRIDIAN_VCPU, h, &ctxt) != 0 )
        return -EINVAL;

    if ( memcmp(&ctxt._pad, zero_page, sizeof(ctxt._pad)) )
        return -EINVAL;

    viridian_synic_load_vcpu_ctxt(v, &ctxt);
    viridian_time_load_vcpu_ctxt(v, &ctxt);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VIRIDIAN_VCPU, viridian_save_vcpu_ctxt,
                          viridian_load_vcpu_ctxt, 1, HVMSR_PER_VCPU);

static int __init parse_viridian_version(const char *arg)
{
    const char *t;
    unsigned int n[3];
    unsigned int i = 0;

    n[0] = viridian_major;
    n[1] = viridian_minor;
    n[2] = viridian_build;

    do {
        const char *e;

        t = strchr(arg, ',');
        if ( !t )
            t = strchr(arg, '\0');

        if ( *arg && *arg != ',' && i < 3 )
        {
            n[i] = simple_strtoul(arg, &e, 0);
            if ( e != t )
                break;
        }

        i++;
        arg = t + 1;
    } while ( *t );

    if ( i != 3 )
        return -EINVAL;

    if ( ((typeof(viridian_major))n[0] != n[0]) ||
         ((typeof(viridian_minor))n[1] != n[1]) ||
         ((typeof(viridian_build))n[2] != n[2]) )
        return -EINVAL;

    viridian_major = n[0];
    viridian_minor = n[1];
    viridian_build = n[2];

    printk("viridian-version = %#x,%#x,%#x\n",
           viridian_major, viridian_minor, viridian_build);
    return 0;
}
custom_param("viridian-version", parse_viridian_version);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
