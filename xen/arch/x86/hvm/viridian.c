/******************************************************************************
 * viridian.c
 *
 * An implementation of some Viridian enlightenments. See Microsoft's
 * Hypervisor Top Level Functional Specification (v5.0a) at:
 *
 * https://github.com/Microsoft/Virtualization-Documentation/raw/master/tlfs/Hypervisor%20Top%20Level%20Functional%20Specification%20v5.0.pdf 
 *
 * for more information.
 */

#include <xen/sched.h>
#include <xen/version.h>
#include <xen/perfc.h>
#include <xen/hypercall.h>
#include <xen/domain_page.h>
#include <asm/guest_access.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/apic.h>
#include <asm/hvm/support.h>
#include <public/sched.h>
#include <public/hvm/hvm_op.h>

/* Viridian MSR numbers. */
#define HV_X64_MSR_GUEST_OS_ID                   0x40000000
#define HV_X64_MSR_HYPERCALL                     0x40000001
#define HV_X64_MSR_VP_INDEX                      0x40000002
#define HV_X64_MSR_RESET                         0x40000003
#define HV_X64_MSR_VP_RUNTIME                    0x40000010
#define HV_X64_MSR_TIME_REF_COUNT                0x40000020
#define HV_X64_MSR_REFERENCE_TSC                 0x40000021
#define HV_X64_MSR_TSC_FREQUENCY                 0x40000022
#define HV_X64_MSR_APIC_FREQUENCY                0x40000023
#define HV_X64_MSR_EOI                           0x40000070
#define HV_X64_MSR_ICR                           0x40000071
#define HV_X64_MSR_TPR                           0x40000072
#define HV_X64_MSR_VP_ASSIST_PAGE                0x40000073
#define HV_X64_MSR_SCONTROL                      0x40000080
#define HV_X64_MSR_SVERSION                      0x40000081
#define HV_X64_MSR_SIEFP                         0x40000082
#define HV_X64_MSR_SIMP                          0x40000083
#define HV_X64_MSR_EOM                           0x40000084
#define HV_X64_MSR_SINT0                         0x40000090
#define HV_X64_MSR_SINT1                         0x40000091
#define HV_X64_MSR_SINT2                         0x40000092
#define HV_X64_MSR_SINT3                         0x40000093
#define HV_X64_MSR_SINT4                         0x40000094
#define HV_X64_MSR_SINT5                         0x40000095
#define HV_X64_MSR_SINT6                         0x40000096
#define HV_X64_MSR_SINT7                         0x40000097
#define HV_X64_MSR_SINT8                         0x40000098
#define HV_X64_MSR_SINT9                         0x40000099
#define HV_X64_MSR_SINT10                        0x4000009A
#define HV_X64_MSR_SINT11                        0x4000009B
#define HV_X64_MSR_SINT12                        0x4000009C
#define HV_X64_MSR_SINT13                        0x4000009D
#define HV_X64_MSR_SINT14                        0x4000009E
#define HV_X64_MSR_SINT15                        0x4000009F
#define HV_X64_MSR_STIMER0_CONFIG                0x400000B0
#define HV_X64_MSR_STIMER0_COUNT                 0x400000B1
#define HV_X64_MSR_STIMER1_CONFIG                0x400000B2
#define HV_X64_MSR_STIMER1_COUNT                 0x400000B3
#define HV_X64_MSR_STIMER2_CONFIG                0x400000B4
#define HV_X64_MSR_STIMER2_COUNT                 0x400000B5
#define HV_X64_MSR_STIMER3_CONFIG                0x400000B6
#define HV_X64_MSR_STIMER3_COUNT                 0x400000B7
#define HV_X64_MSR_POWER_STATE_TRIGGER_C1        0x400000C1
#define HV_X64_MSR_POWER_STATE_TRIGGER_C2        0x400000C2
#define HV_X64_MSR_POWER_STATE_TRIGGER_C3        0x400000C3
#define HV_X64_MSR_POWER_STATE_CONFIG_C1         0x400000D1
#define HV_X64_MSR_POWER_STATE_CONFIG_C2         0x400000D2
#define HV_X64_MSR_POWER_STATE_CONFIG_C3         0x400000D3
#define HV_X64_MSR_STATS_PARTITION_RETAIL_PAGE   0x400000E0
#define HV_X64_MSR_STATS_PARTITION_INTERNAL_PAGE 0x400000E1
#define HV_X64_MSR_STATS_VP_RETAIL_PAGE          0x400000E2
#define HV_X64_MSR_STATS_VP_INTERNAL_PAGE        0x400000E3
#define HV_X64_MSR_GUEST_IDLE                    0x400000F0
#define HV_X64_MSR_SYNTH_DEBUG_CONTROL           0x400000F1
#define HV_X64_MSR_SYNTH_DEBUG_STATUS            0x400000F2
#define HV_X64_MSR_SYNTH_DEBUG_SEND_BUFFER       0x400000F3
#define HV_X64_MSR_SYNTH_DEBUG_RECEIVE_BUFFER    0x400000F4
#define HV_X64_MSR_SYNTH_DEBUG_PENDING_BUFFER    0x400000F5
#define HV_X64_MSR_CRASH_P0                      0x40000100
#define HV_X64_MSR_CRASH_P1                      0x40000101
#define HV_X64_MSR_CRASH_P2                      0x40000102
#define HV_X64_MSR_CRASH_P3                      0x40000103
#define HV_X64_MSR_CRASH_P4                      0x40000104
#define HV_X64_MSR_CRASH_CTL                     0x40000105

#define VIRIDIAN_MSR_MIN HV_X64_MSR_GUEST_OS_ID
#define VIRIDIAN_MSR_MAX HV_X64_MSR_CRASH_CTL

/* Viridian Hypercall Status Codes. */
#define HV_STATUS_SUCCESS                       0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE        0x0002
#define HV_STATUS_INVALID_PARAMETER             0x0005

/* Viridian Hypercall Codes. */
#define HvFlushVirtualAddressSpace 0x0002
#define HvFlushVirtualAddressList  0x0003
#define HvNotifyLongSpinWait       0x0008
#define HvGetPartitionId           0x0046
#define HvExtCallQueryCapabilities 0x8001

/* Viridian Hypercall Flags. */
#define HV_FLUSH_ALL_PROCESSORS 1

/*
 * Viridian Partition Privilege Flags.
 *
 * This is taken from section 4.2.2 of the specification, and fixed for
 * style and correctness.
 */
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

/* Viridian CPUID leaf 4: Implementation Recommendations. */
#define CPUID4A_HCALL_REMOTE_TLB_FLUSH (1 << 2)
#define CPUID4A_MSR_BASED_APIC         (1 << 3)
#define CPUID4A_RELAX_TIMER_INT        (1 << 5)

/* Viridian CPUID leaf 6: Implementation HW features detected and in use. */
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

    ASSERT(is_viridian_domain(d));
    ASSERT(leaf >= 0x40000000 && leaf < 0x40000100);

    leaf -= 0x40000000;

    switch ( leaf )
    {
    case 0:
        /* See section 2.4.1 of the specification */
        res->a = 0x40000006; /* Maximum leaf */
        memcpy(&res->b, "Micr", 4);
        memcpy(&res->c, "osof", 4);
        memcpy(&res->d, "t Hv", 4);
        break;

    case 1:
        /* See section 2.4.2 of the specification */
        memcpy(&res->a, "Hv#1", 4);
        break;

    case 2:
        /* Hypervisor information, but only if the guest has set its
           own version number. */
        if ( d->arch.hvm_domain.viridian.guest_os_id.raw == 0 )
            break;
        res->a = viridian_build;
        res->b = ((uint32_t)viridian_major << 16) | viridian_minor;
        res->c = 0; /* SP */
        res->d = 0; /* Service branch and number */
        break;

    case 3:
    {
        /*
         * Section 2.4.4 details this leaf and states that EAX and EBX
         * are defined to be the low and high parts of the partition
         * privilege mask respectively.
         */
        HV_PARTITION_PRIVILEGE_MASK mask = {
            .AccessIntrCtrlRegs = 1,
            .AccessHypercallMsrs = 1,
            .AccessVpIndex = 1,
        };
        union {
            HV_PARTITION_PRIVILEGE_MASK mask;
            uint32_t lo, hi;
        } u;

        if ( !(viridian_feature_mask(d) & HVMPV_no_freq) )
            mask.AccessFrequencyRegs = 1;
        if ( viridian_feature_mask(d) & HVMPV_time_ref_count )
            mask.AccessPartitionReferenceCounter = 1;
        if ( viridian_feature_mask(d) & HVMPV_reference_tsc )
            mask.AccessPartitionReferenceTsc = 1;

        u.mask = mask;

        res->a = u.lo;
        res->b = u.hi;

        if ( viridian_feature_mask(d) & HVMPV_crash_ctl )
            res->d = CPUID3D_CRASH_MSRS;

        break;
    }

    case 4:
        /* Recommended hypercall usage. */
        if ( (d->arch.hvm_domain.viridian.guest_os_id.raw == 0) ||
             (d->arch.hvm_domain.viridian.guest_os_id.fields.os < 4) )
            break;
        res->a = CPUID4A_RELAX_TIMER_INT;
        if ( viridian_feature_mask(d) & HVMPV_hcall_remote_tlb_flush )
            res->a |= CPUID4A_HCALL_REMOTE_TLB_FLUSH;
        if ( !cpu_has_vmx_apic_reg_virt )
            res->a |= CPUID4A_MSR_BASED_APIC;

        /*
         * This value is the recommended number of attempts to try to
         * acquire a spinlock before notifying the hypervisor via the
         * HvNotifyLongSpinWait hypercall.
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
    const union viridian_guest_os_id *goi;

    goi = &d->arch.hvm_domain.viridian.guest_os_id;

    printk(XENLOG_G_INFO
           "d%d: VIRIDIAN GUEST_OS_ID: vendor: %x os: %x major: %x minor: %x sp: %x build: %x\n",
           d->domain_id,
           goi->fields.vendor, goi->fields.os,
           goi->fields.major, goi->fields.minor,
           goi->fields.service_pack, goi->fields.build_number);
}

static void dump_hypercall(const struct domain *d)
{
    const union viridian_hypercall_gpa *hg;

    hg = &d->arch.hvm_domain.viridian.hypercall_gpa;

    printk(XENLOG_G_INFO "d%d: VIRIDIAN HYPERCALL: enabled: %x pfn: %lx\n",
           d->domain_id,
           hg->fields.enabled, (unsigned long)hg->fields.pfn);
}

static void dump_vp_assist(const struct vcpu *v)
{
    const union viridian_vp_assist *va;

    va = &v->arch.hvm_vcpu.viridian.vp_assist.msr;

    printk(XENLOG_G_INFO "%pv: VIRIDIAN VP_ASSIST_PAGE: enabled: %x pfn: %lx\n",
           v, va->fields.enabled, (unsigned long)va->fields.pfn);
}

static void dump_reference_tsc(const struct domain *d)
{
    const union viridian_reference_tsc *rt;

    rt = &d->arch.hvm_domain.viridian.reference_tsc;
    
    printk(XENLOG_G_INFO "d%d: VIRIDIAN REFERENCE_TSC: enabled: %x pfn: %lx\n",
           d->domain_id,
           rt->fields.enabled, (unsigned long)rt->fields.pfn);
}

static void enable_hypercall_page(struct domain *d)
{
    unsigned long gmfn = d->arch.hvm_domain.viridian.hypercall_gpa.fields.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    uint8_t *p;

    if ( !page || !get_page_type(page, PGT_writable_page) )
    {
        if ( page )
            put_page(page);
        gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n",
                 gmfn, page ? page_to_mfn(page) : mfn_x(INVALID_MFN));
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

static void initialize_vp_assist(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long gmfn = v->arch.hvm_vcpu.viridian.vp_assist.msr.fields.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    void *va;

    ASSERT(!v->arch.hvm_vcpu.viridian.vp_assist.va);

    /*
     * See section 7.8.7 of the specification for details of this
     * enlightenment.
     */

    if ( !page )
        goto fail;

    if ( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        goto fail;
    }

    va = __map_domain_page_global(page);
    if ( !va )
    {
        put_page_and_type(page);
        goto fail;
    }

    clear_page(va);

    v->arch.hvm_vcpu.viridian.vp_assist.va = va;
    return;

 fail:
    gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n", gmfn,
             page ? page_to_mfn(page) : mfn_x(INVALID_MFN));
}

static void teardown_vp_assist(struct vcpu *v)
{
    void *va = v->arch.hvm_vcpu.viridian.vp_assist.va;
    struct page_info *page;

    if ( !va )
        return;

    v->arch.hvm_vcpu.viridian.vp_assist.va = NULL;

    page = mfn_to_page(domain_page_map_to_mfn(va));

    unmap_domain_page_global(va);
    put_page_and_type(page);
}

void viridian_apic_assist_set(struct vcpu *v)
{
    uint32_t *va = v->arch.hvm_vcpu.viridian.vp_assist.va;

    if ( !va )
        return;

    /*
     * If there is already an assist pending then something has gone
     * wrong and the VM will most likely hang so force a crash now
     * to make the problem clear.
     */
    if ( v->arch.hvm_vcpu.viridian.vp_assist.pending )
        domain_crash(v->domain);

    v->arch.hvm_vcpu.viridian.vp_assist.pending = true;
    *va |= 1u;
}

bool viridian_apic_assist_completed(struct vcpu *v)
{
    uint32_t *va = v->arch.hvm_vcpu.viridian.vp_assist.va;

    if ( !va )
        return false;

    if ( v->arch.hvm_vcpu.viridian.vp_assist.pending &&
         !(*va & 1u) )
    {
        /* An EOI has been avoided */
        v->arch.hvm_vcpu.viridian.vp_assist.pending = false;
        return true;
    }

    return false;
}

void viridian_apic_assist_clear(struct vcpu *v)
{
    uint32_t *va = v->arch.hvm_vcpu.viridian.vp_assist.va;

    if ( !va )
        return;

    *va &= ~1u;
    v->arch.hvm_vcpu.viridian.vp_assist.pending = false;
}

static void update_reference_tsc(struct domain *d, bool_t initialize)
{
    unsigned long gmfn = d->arch.hvm_domain.viridian.reference_tsc.fields.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    HV_REFERENCE_TSC_PAGE *p;

    if ( !page || !get_page_type(page, PGT_writable_page) )
    {
        if ( page )
            put_page(page);
        gdprintk(XENLOG_WARNING, "Bad GMFN %#"PRI_gfn" (MFN %#"PRI_mfn")\n",
                 gmfn, page ? page_to_mfn(page) : mfn_x(INVALID_MFN));
        return;
    }

    p = __map_domain_page(page);

    if ( initialize )
        clear_page(p);

    /*
     * This enlightenment must be disabled is the host TSC is not invariant.
     * However it is also disabled if vtsc is true (which means rdtsc is being
     * emulated). This generally happens when guest TSC freq and host TSC freq
     * don't match. The TscScale value could be adjusted to cope with this,
     * allowing vtsc to be turned off, but support for this is not yet present
     * in the hypervisor. Thus is it is possible that migrating a Windows VM
     * between hosts of differing TSC frequencies may result in large
     * differences in guest performance.
     */
    if ( !host_tsc_is_safe() || d->arch.vtsc )
    {
        /*
         * The specification states that valid values of TscSequence range
         * from 0 to 0xFFFFFFFE. The value 0xFFFFFFFF is used to indicate
         * this mechanism is no longer a reliable source of time and that
         * the VM should fall back to a different source.
         *
         * Server 2012 (6.2 kernel) and 2012 R2 (6.3 kernel) actually violate
         * the spec. and rely on a value of 0 to indicate that this
         * enlightenment should no longer be used. These two kernel
         * versions are currently the only ones to make use of this
         * enlightenment, so just use 0 here.
         */
        p->TscSequence = 0;

        printk(XENLOG_G_INFO "d%d: VIRIDIAN REFERENCE_TSC: invalidated\n",
               d->domain_id);
        goto out;
    }

    /*
     * The guest will calculate reference time according to the following
     * formula:
     *
     * ReferenceTime = ((RDTSC() * TscScale) >> 64) + TscOffset
     *
     * Windows uses a 100ns tick, so we need a scale which is cpu
     * ticks per 100ns shifted left by 64.
     */
    p->TscScale = ((10000ul << 32) / d->arch.tsc_khz) << 32;

    p->TscSequence++;
    if ( p->TscSequence == 0xFFFFFFFF ||
         p->TscSequence == 0 ) /* Avoid both 'invalid' values */
        p->TscSequence = 1;

 out:
    unmap_domain_page(p);

    put_page_and_type(page);
}

int wrmsr_viridian_regs(uint32_t idx, uint64_t val)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;

    if ( !is_viridian_domain(d) )
        return 0;

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        perfc_incr(mshv_wrmsr_osid);
        d->arch.hvm_domain.viridian.guest_os_id.raw = val;
        dump_guest_os_id(d);
        break;

    case HV_X64_MSR_HYPERCALL:
        perfc_incr(mshv_wrmsr_hc_page);
        d->arch.hvm_domain.viridian.hypercall_gpa.raw = val;
        dump_hypercall(d);
        if ( d->arch.hvm_domain.viridian.hypercall_gpa.fields.enabled )
            enable_hypercall_page(d);
        break;

    case HV_X64_MSR_VP_INDEX:
        perfc_incr(mshv_wrmsr_vp_index);
        break;

    case HV_X64_MSR_EOI:
        perfc_incr(mshv_wrmsr_eoi);
        vlapic_EOI_set(vcpu_vlapic(v));
        break;

    case HV_X64_MSR_ICR: {
        u32 eax = (u32)val, edx = (u32)(val >> 32);
        struct vlapic *vlapic = vcpu_vlapic(v);
        perfc_incr(mshv_wrmsr_icr);
        eax &= ~(1 << 12);
        edx &= 0xff000000;
        vlapic_set_reg(vlapic, APIC_ICR2, edx);
        vlapic_ipi(vlapic, eax, edx);
        vlapic_set_reg(vlapic, APIC_ICR, eax);
        break;
    }

    case HV_X64_MSR_TPR:
        perfc_incr(mshv_wrmsr_tpr);
        vlapic_set_reg(vcpu_vlapic(v), APIC_TASKPRI, (uint8_t)val);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        perfc_incr(mshv_wrmsr_apic_msr);
        teardown_vp_assist(v); /* release any previous mapping */
        v->arch.hvm_vcpu.viridian.vp_assist.msr.raw = val;
        dump_vp_assist(v);
        if ( v->arch.hvm_vcpu.viridian.vp_assist.msr.fields.enabled )
            initialize_vp_assist(v);
        break;

    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return 0;

        perfc_incr(mshv_wrmsr_tsc_msr);
        d->arch.hvm_domain.viridian.reference_tsc.raw = val;
        dump_reference_tsc(d);
        if ( d->arch.hvm_domain.viridian.reference_tsc.fields.enabled )
            update_reference_tsc(d, 1);
        break;

    case HV_X64_MSR_CRASH_P0:
    case HV_X64_MSR_CRASH_P1:
    case HV_X64_MSR_CRASH_P2:
    case HV_X64_MSR_CRASH_P3:
    case HV_X64_MSR_CRASH_P4:
        BUILD_BUG_ON(HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 >=
                     ARRAY_SIZE(v->arch.hvm_vcpu.viridian.crash_param));

        idx -= HV_X64_MSR_CRASH_P0;
        v->arch.hvm_vcpu.viridian.crash_param[idx] = val;
        break;

    case HV_X64_MSR_CRASH_CTL:
    {
        HV_CRASH_CTL_REG_CONTENTS ctl;

        ctl.AsUINT64 = val;

        if ( !ctl.u.CrashNotify )
            break;

        gprintk(XENLOG_WARNING, "VIRIDIAN CRASH: %lx %lx %lx %lx %lx\n",
                v->arch.hvm_vcpu.viridian.crash_param[0],
                v->arch.hvm_vcpu.viridian.crash_param[1],
                v->arch.hvm_vcpu.viridian.crash_param[2],
                v->arch.hvm_vcpu.viridian.crash_param[3],
                v->arch.hvm_vcpu.viridian.crash_param[4]);
        break;
    }

    default:
        if ( idx >= VIRIDIAN_MSR_MIN && idx <= VIRIDIAN_MSR_MAX )
            gprintk(XENLOG_WARNING, "write to unimplemented MSR %#x\n",
                    idx);

        return 0;
    }

    return 1;
}

static int64_t raw_trc_val(struct domain *d)
{
    uint64_t tsc;
    struct time_scale tsc_to_ns;

    tsc = hvm_get_guest_tsc(pt_global_vcpu_target(d));

    /* convert tsc to count of 100ns periods */
    set_time_scale(&tsc_to_ns, d->arch.tsc_khz * 1000ul);
    return scale_delta(tsc, &tsc_to_ns) / 100ul;
}

void viridian_time_ref_count_freeze(struct domain *d)
{
    struct viridian_time_ref_count *trc;

    trc = &d->arch.hvm_domain.viridian.time_ref_count;

    if ( test_and_clear_bit(_TRC_running, &trc->flags) )
        trc->val = raw_trc_val(d) + trc->off;
}

void viridian_time_ref_count_thaw(struct domain *d)
{
    struct viridian_time_ref_count *trc;

    trc = &d->arch.hvm_domain.viridian.time_ref_count;

    if ( !d->is_shutting_down &&
         !test_and_set_bit(_TRC_running, &trc->flags) )
        trc->off = (int64_t)trc->val - raw_trc_val(d);
}

int rdmsr_viridian_regs(uint32_t idx, uint64_t *val)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    
    if ( !is_viridian_domain(d) )
        return 0;

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        perfc_incr(mshv_rdmsr_osid);
        *val = d->arch.hvm_domain.viridian.guest_os_id.raw;
        break;

    case HV_X64_MSR_HYPERCALL:
        perfc_incr(mshv_rdmsr_hc_page);
        *val = d->arch.hvm_domain.viridian.hypercall_gpa.raw;
        break;

    case HV_X64_MSR_VP_INDEX:
        perfc_incr(mshv_rdmsr_vp_index);
        *val = v->vcpu_id;
        break;

    case HV_X64_MSR_TSC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return 0;

        perfc_incr(mshv_rdmsr_tsc_frequency);
        *val = (uint64_t)d->arch.tsc_khz * 1000ull;
        break;

    case HV_X64_MSR_APIC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return 0;

        perfc_incr(mshv_rdmsr_apic_frequency);
        *val = 1000000000ull / APIC_BUS_CYCLE_NS;
        break;

    case HV_X64_MSR_ICR:
        perfc_incr(mshv_rdmsr_icr);
        *val = (((uint64_t)vlapic_get_reg(vcpu_vlapic(v), APIC_ICR2) << 32) |
                vlapic_get_reg(vcpu_vlapic(v), APIC_ICR));
        break;

    case HV_X64_MSR_TPR:
        perfc_incr(mshv_rdmsr_tpr);
        *val = vlapic_get_reg(vcpu_vlapic(v), APIC_TASKPRI);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        perfc_incr(mshv_rdmsr_apic_msr);
        *val = v->arch.hvm_vcpu.viridian.vp_assist.msr.raw;
        break;

    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return 0;

        perfc_incr(mshv_rdmsr_tsc_msr);
        *val = d->arch.hvm_domain.viridian.reference_tsc.raw;
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
    {
        struct viridian_time_ref_count *trc;

        trc = &d->arch.hvm_domain.viridian.time_ref_count;

        if ( !(viridian_feature_mask(d) & HVMPV_time_ref_count) )
            return 0;

        if ( !test_and_set_bit(_TRC_accessed, &trc->flags) )
            printk(XENLOG_G_INFO "d%d: VIRIDIAN MSR_TIME_REF_COUNT: accessed\n",
                   d->domain_id);

        perfc_incr(mshv_rdmsr_time_ref_count);
        *val = raw_trc_val(d) + trc->off;
        break;
    }

    case HV_X64_MSR_CRASH_P0:
    case HV_X64_MSR_CRASH_P1:
    case HV_X64_MSR_CRASH_P2:
    case HV_X64_MSR_CRASH_P3:
    case HV_X64_MSR_CRASH_P4:
        BUILD_BUG_ON(HV_X64_MSR_CRASH_P4 - HV_X64_MSR_CRASH_P0 >=
                     ARRAY_SIZE(v->arch.hvm_vcpu.viridian.crash_param));

        idx -= HV_X64_MSR_CRASH_P0;
        *val = v->arch.hvm_vcpu.viridian.crash_param[idx];
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
        if ( idx >= VIRIDIAN_MSR_MIN && idx <= VIRIDIAN_MSR_MAX )
            gprintk(XENLOG_WARNING, "read from unimplemented MSR %#x\n",
                    idx);

        return 0;
    }

    return 1;
}

void viridian_vcpu_deinit(struct vcpu *v)
{
    teardown_vp_assist(v);
}

void viridian_domain_deinit(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        teardown_vp_assist(v);
}

static DEFINE_PER_CPU(cpumask_t, ipi_cpumask);

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
    case HvNotifyLongSpinWait:
        /*
         * See section 14.5.1 of the specification.
         */
        perfc_incr(mshv_call_long_wait);
        do_sched_op(SCHEDOP_yield, guest_handle_from_ptr(NULL, void));
        status = HV_STATUS_SUCCESS;
        break;

    case HvFlushVirtualAddressSpace:
    case HvFlushVirtualAddressList:
    {
        cpumask_t *pcpu_mask;
        struct vcpu *v;
        struct {
            uint64_t address_space;
            uint64_t flags;
            uint64_t vcpu_mask;
        } input_params;

        /*
         * See sections 9.4.2 and 9.4.4 of the specification.
         */
        perfc_incr(mshv_call_flush);

        /* These hypercalls should never use the fast-call convention. */
        status = HV_STATUS_INVALID_PARAMETER;
        if ( input.fast )
            break;

        /* Get input parameters. */
        if ( hvm_copy_from_guest_phys(&input_params, input_params_gpa,
                                      sizeof(input_params)) != HVMTRANS_okay )
            break;

        /*
         * It is not clear from the spec. if we are supposed to
         * include current virtual CPU in the set or not in this case,
         * so err on the safe side.
         */
        if ( input_params.flags & HV_FLUSH_ALL_PROCESSORS )
            input_params.vcpu_mask = ~0ul;

        pcpu_mask = &this_cpu(ipi_cpumask);
        cpumask_clear(pcpu_mask);

        /*
         * For each specified virtual CPU flush all ASIDs to invalidate
         * TLB entries the next time it is scheduled and then, if it
         * is currently running, add its physical CPU to a mask of
         * those which need to be interrupted to force a flush.
         */
        for_each_vcpu ( currd, v )
        {
            if ( v->vcpu_id >= (sizeof(input_params.vcpu_mask) * 8) )
                break;

            if ( !(input_params.vcpu_mask & (1ul << v->vcpu_id)) )
                continue;

            hvm_asid_flush_vcpu(v);
            if ( v != curr && v->is_running )
                __cpumask_set_cpu(v->processor, pcpu_mask);
        }

        /*
         * Since ASIDs have now been flushed it just remains to
         * force any CPUs currently running target vCPUs out of non-
         * root mode. It's possible that re-scheduling has taken place
         * so we may unnecessarily IPI some CPUs.
         */
        if ( !cpumask_empty(pcpu_mask) )
            smp_send_event_check_mask(pcpu_mask);

        output.rep_complete = input.rep_count;

        status = HV_STATUS_SUCCESS;
        break;
    }

    default:
        gprintk(XENLOG_WARNING, "unimplemented hypercall %04x\n",
                input.call_code);
        /* Fallthrough. */
    case HvGetPartitionId:
    case HvExtCallQueryCapabilities:
        /*
         * These hypercalls seem to be erroneously issued by Windows
         * despite neither AccessPartitionId nor EnableExtendedHypercalls
         * being set in CPUID leaf 2.
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

static int viridian_save_domain_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_viridian_domain_context ctxt = {
        .time_ref_count = d->arch.hvm_domain.viridian.time_ref_count.val,
        .hypercall_gpa  = d->arch.hvm_domain.viridian.hypercall_gpa.raw,
        .guest_os_id    = d->arch.hvm_domain.viridian.guest_os_id.raw,
        .reference_tsc  = d->arch.hvm_domain.viridian.reference_tsc.raw,
    };

    if ( !is_viridian_domain(d) )
        return 0;

    return (hvm_save_entry(VIRIDIAN_DOMAIN, 0, h, &ctxt) != 0);
}

static int viridian_load_domain_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_viridian_domain_context ctxt;

    if ( hvm_load_entry_zeroextend(VIRIDIAN_DOMAIN, h, &ctxt) != 0 )
        return -EINVAL;

    d->arch.hvm_domain.viridian.time_ref_count.val = ctxt.time_ref_count;
    d->arch.hvm_domain.viridian.hypercall_gpa.raw  = ctxt.hypercall_gpa;
    d->arch.hvm_domain.viridian.guest_os_id.raw    = ctxt.guest_os_id;
    d->arch.hvm_domain.viridian.reference_tsc.raw  = ctxt.reference_tsc;

    if ( d->arch.hvm_domain.viridian.reference_tsc.fields.enabled )
        update_reference_tsc(d, 0);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VIRIDIAN_DOMAIN, viridian_save_domain_ctxt,
                          viridian_load_domain_ctxt, 1, HVMSR_PER_DOM);

static int viridian_save_vcpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;

    if ( !is_viridian_domain(d) )
        return 0;

    for_each_vcpu( d, v ) {
        struct hvm_viridian_vcpu_context ctxt = {
            .vp_assist_msr = v->arch.hvm_vcpu.viridian.vp_assist.msr.raw,
            .vp_assist_pending = v->arch.hvm_vcpu.viridian.vp_assist.pending,
        };

        if ( hvm_save_entry(VIRIDIAN_VCPU, v->vcpu_id, h, &ctxt) != 0 )
            return 1;
    }

    return 0;
}

static int viridian_load_vcpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid;
    struct vcpu *v;
    struct hvm_viridian_vcpu_context ctxt;

    vcpuid = hvm_load_instance(h);
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

    v->arch.hvm_vcpu.viridian.vp_assist.msr.raw = ctxt.vp_assist_msr;
    if ( v->arch.hvm_vcpu.viridian.vp_assist.msr.fields.enabled &&
         !v->arch.hvm_vcpu.viridian.vp_assist.va )
        initialize_vp_assist(v);

    v->arch.hvm_vcpu.viridian.vp_assist.pending = !!ctxt.vp_assist_pending;

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
