/******************************************************************************
 * viridian.c
 *
 * An implementation of the Viridian hypercall interface.
 */

#include <xen/sched.h>
#include <xen/version.h>
#include <xen/perfc.h>
#include <xen/hypercall.h>
#include <xen/domain_page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/apic.h>
#include <asm/hvm/support.h>
#include <public/sched.h>
#include <public/hvm/hvm_op.h>

/* Viridian MSR numbers. */
#define VIRIDIAN_MSR_GUEST_OS_ID                0x40000000
#define VIRIDIAN_MSR_HYPERCALL                  0x40000001
#define VIRIDIAN_MSR_VP_INDEX                   0x40000002
#define VIRIDIAN_MSR_TIME_REF_COUNT             0x40000020
#define VIRIDIAN_MSR_TSC_FREQUENCY              0x40000022
#define VIRIDIAN_MSR_APIC_FREQUENCY             0x40000023
#define VIRIDIAN_MSR_EOI                        0x40000070
#define VIRIDIAN_MSR_ICR                        0x40000071
#define VIRIDIAN_MSR_TPR                        0x40000072
#define VIRIDIAN_MSR_APIC_ASSIST                0x40000073

/* Viridian Hypercall Status Codes. */
#define HV_STATUS_SUCCESS                       0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE        0x0002

/* Viridian Hypercall Codes and Parameters. */
#define HvNotifyLongSpinWait    8

/* Viridian CPUID 4000003, Viridian MSR availability. */
#define CPUID3A_MSR_TIME_REF_COUNT (1 << 1)
#define CPUID3A_MSR_APIC_ACCESS    (1 << 4)
#define CPUID3A_MSR_HYPERCALL      (1 << 5)
#define CPUID3A_MSR_VP_INDEX       (1 << 6)
#define CPUID3A_MSR_FREQ           (1 << 11)

/* Viridian CPUID 4000004, Implementation Recommendations. */
#define CPUID4A_MSR_BASED_APIC  (1 << 3)
#define CPUID4A_RELAX_TIMER_INT (1 << 5)

/* Viridian CPUID 4000006, Implementation HW features detected and in use. */
#define CPUID6A_APIC_OVERLAY    (1 << 0)
#define CPUID6A_MSR_BITMAPS     (1 << 1)
#define CPUID6A_NESTED_PAGING   (1 << 3)

int cpuid_viridian_leaves(unsigned int leaf, unsigned int *eax,
                          unsigned int *ebx, unsigned int *ecx,
                          unsigned int *edx)
{
    struct domain *d = current->domain;

    if ( !is_viridian_domain(d) )
        return 0;

    leaf -= 0x40000000;
    if ( leaf > 6 )
        return 0;

    *eax = *ebx = *ecx = *edx = 0;
    switch ( leaf )
    {
    case 0:
        *eax = 0x40000006; /* Maximum leaf */
        *ebx = 0x7263694d; /* Magic numbers  */
        *ecx = 0x666F736F;
        *edx = 0x76482074;
        break;
    case 1:
        *eax = 0x31237648; /* Version number */
        break;
    case 2:
        /* Hypervisor information, but only if the guest has set its
           own version number. */
        if ( d->arch.hvm_domain.viridian.guest_os_id.raw == 0 )
            break;
        *eax = 1; /* Build number */
        *ebx = (xen_major_version() << 16) | xen_minor_version();
        *ecx = 0; /* SP */
        *edx = 0; /* Service branch and number */
        break;
    case 3:
        /* Which hypervisor MSRs are available to the guest */
        *eax = (CPUID3A_MSR_APIC_ACCESS |
                CPUID3A_MSR_HYPERCALL   |
                CPUID3A_MSR_VP_INDEX);
        if ( !(viridian_feature_mask(d) & HVMPV_no_freq) )
            *eax |= CPUID3A_MSR_FREQ;
        if ( viridian_feature_mask(d) & HVMPV_time_ref_count )
            *eax |= CPUID3A_MSR_TIME_REF_COUNT;
        break;
    case 4:
        /* Recommended hypercall usage. */
        if ( (d->arch.hvm_domain.viridian.guest_os_id.raw == 0) ||
             (d->arch.hvm_domain.viridian.guest_os_id.fields.os < 4) )
            break;
        *eax = CPUID4A_RELAX_TIMER_INT;
        if ( !cpu_has_vmx_apic_reg_virt )
            *eax |= CPUID4A_MSR_BASED_APIC;
        *ebx = 2047; /* long spin count */
        break;
    case 6:
        /* Detected and in use hardware features. */
        if ( cpu_has_vmx_virtualize_apic_accesses )
            *eax |= CPUID6A_APIC_OVERLAY;
        if ( cpu_has_vmx_msr_bitmap || (read_efer() & EFER_SVME) )
            *eax |= CPUID6A_MSR_BITMAPS;
        if ( hap_enabled(d) )
            *eax |= CPUID6A_NESTED_PAGING;
        break;
    }

    return 1;
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

static void dump_apic_assist(const struct vcpu *v)
{
    const union viridian_apic_assist *aa;

    aa = &v->arch.hvm_vcpu.viridian.apic_assist;

    printk(XENLOG_G_INFO "%pv: VIRIDIAN APIC_ASSIST: enabled: %x pfn: %lx\n",
           v, aa->fields.enabled, (unsigned long)aa->fields.pfn);
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
        gdprintk(XENLOG_WARNING, "Bad GMFN %lx (MFN %lx)\n", gmfn,
                 page ? page_to_mfn(page) : INVALID_MFN);
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

static void initialize_apic_assist(struct vcpu *v)
{
    struct domain *d = v->domain;
    unsigned long gmfn = v->arch.hvm_vcpu.viridian.apic_assist.fields.pfn;
    struct page_info *page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);
    uint8_t *p;

    /*
     * We don't yet make use of the APIC assist page but by setting
     * the CPUID3A_MSR_APIC_ACCESS bit in CPUID leaf 40000003 we are duty
     * bound to support the MSR. We therefore do just enough to keep windows
     * happy.
     *
     * See http://msdn.microsoft.com/en-us/library/ff538657%28VS.85%29.aspx for
     * details of how Windows uses the page.
     */

    if ( !page || !get_page_type(page, PGT_writable_page) )
    {
        if ( page )
            put_page(page);
        gdprintk(XENLOG_WARNING, "Bad GMFN %lx (MFN %lx)\n", gmfn,
                 page ? page_to_mfn(page) : INVALID_MFN);
        return;
    }

    p = __map_domain_page(page);

    *(u32 *)p = 0;

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
    case VIRIDIAN_MSR_GUEST_OS_ID:
        perfc_incr(mshv_wrmsr_osid);
        d->arch.hvm_domain.viridian.guest_os_id.raw = val;
        dump_guest_os_id(d);
        break;

    case VIRIDIAN_MSR_HYPERCALL:
        perfc_incr(mshv_wrmsr_hc_page);
        d->arch.hvm_domain.viridian.hypercall_gpa.raw = val;
        dump_hypercall(d);
        if ( d->arch.hvm_domain.viridian.hypercall_gpa.fields.enabled )
            enable_hypercall_page(d);
        break;

    case VIRIDIAN_MSR_VP_INDEX:
        perfc_incr(mshv_wrmsr_vp_index);
        break;

    case VIRIDIAN_MSR_EOI:
        perfc_incr(mshv_wrmsr_eoi);
        vlapic_EOI_set(vcpu_vlapic(v));
        break;

    case VIRIDIAN_MSR_ICR: {
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

    case VIRIDIAN_MSR_TPR:
        perfc_incr(mshv_wrmsr_tpr);
        vlapic_set_reg(vcpu_vlapic(v), APIC_TASKPRI, (uint8_t)val);
        break;

    case VIRIDIAN_MSR_APIC_ASSIST:
        perfc_incr(mshv_wrmsr_apic_msr);
        v->arch.hvm_vcpu.viridian.apic_assist.raw = val;
        dump_apic_assist(v);
        if (v->arch.hvm_vcpu.viridian.apic_assist.fields.enabled)
            initialize_apic_assist(v);
        break;

    default:
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
    case VIRIDIAN_MSR_GUEST_OS_ID:
        perfc_incr(mshv_rdmsr_osid);
        *val = d->arch.hvm_domain.viridian.guest_os_id.raw;
        break;

    case VIRIDIAN_MSR_HYPERCALL:
        perfc_incr(mshv_rdmsr_hc_page);
        *val = d->arch.hvm_domain.viridian.hypercall_gpa.raw;
        break;

    case VIRIDIAN_MSR_VP_INDEX:
        perfc_incr(mshv_rdmsr_vp_index);
        *val = v->vcpu_id;
        break;

    case VIRIDIAN_MSR_TSC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return 0;

        perfc_incr(mshv_rdmsr_tsc_frequency);
        *val = (uint64_t)d->arch.tsc_khz * 1000ull;
        break;

    case VIRIDIAN_MSR_APIC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return 0;

        perfc_incr(mshv_rdmsr_apic_frequency);
        *val = 1000000000ull / APIC_BUS_CYCLE_NS;
        break;

    case VIRIDIAN_MSR_ICR:
        perfc_incr(mshv_rdmsr_icr);
        *val = (((uint64_t)vlapic_get_reg(vcpu_vlapic(v), APIC_ICR2) << 32) |
                vlapic_get_reg(vcpu_vlapic(v), APIC_ICR));
        break;

    case VIRIDIAN_MSR_TPR:
        perfc_incr(mshv_rdmsr_tpr);
        *val = vlapic_get_reg(vcpu_vlapic(v), APIC_TASKPRI);
        break;

    case VIRIDIAN_MSR_APIC_ASSIST:
        perfc_incr(mshv_rdmsr_apic_msr);
        *val = v->arch.hvm_vcpu.viridian.apic_assist.raw;
        break;

    case VIRIDIAN_MSR_TIME_REF_COUNT:
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

    default:
        return 0;
    }

    return 1;
}

int viridian_hypercall(struct cpu_user_regs *regs)
{
    int mode = hvm_guest_x86_mode(current);
    unsigned long input_params_gpa, output_params_gpa;
    uint16_t status = HV_STATUS_SUCCESS;

    union hypercall_input {
        uint64_t raw;
        struct {
            uint16_t call_code;
            uint16_t rsvd1;
            unsigned rep_count:12;
            unsigned rsvd2:4;
            unsigned rep_start:12;
            unsigned rsvd3:4;
        };
    } input;

    union hypercall_output {
        uint64_t raw;
        struct {
            uint16_t result;
            uint16_t rsvd1;
            unsigned rep_complete:12;
            unsigned rsvd2:20;
        };
    } output = { 0 };

    ASSERT(is_viridian_domain(current->domain));

    switch ( mode )
    {
    case 8:
        input.raw = regs->rcx;
        input_params_gpa = regs->rdx;
        output_params_gpa = regs->r8;
        break;
    case 4:
        input.raw = ((uint64_t)regs->edx << 32) | regs->eax;
        input_params_gpa = ((uint64_t)regs->ebx << 32) | regs->ecx;
        output_params_gpa = ((uint64_t)regs->edi << 32) | regs->esi;
        break;
    default:
        goto out;
    }

    switch ( input.call_code )
    {
    case HvNotifyLongSpinWait:
        perfc_incr(mshv_call_long_wait);
        do_sched_op_compat(SCHEDOP_yield, 0);
        status = HV_STATUS_SUCCESS;
        break;
    default:
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
        regs->edx = output.raw >> 32;
        regs->eax = output.raw;
        break;
    }

    return HVM_HCALL_completed;
}

static int viridian_save_domain_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_viridian_domain_context ctxt;

    if ( !is_viridian_domain(d) )
        return 0;

    ctxt.time_ref_count = d->arch.hvm_domain.viridian.time_ref_count.val;
    ctxt.hypercall_gpa  = d->arch.hvm_domain.viridian.hypercall_gpa.raw;
    ctxt.guest_os_id    = d->arch.hvm_domain.viridian.guest_os_id.raw;

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
        struct hvm_viridian_vcpu_context ctxt;

        ctxt.apic_assist = v->arch.hvm_vcpu.viridian.apic_assist.raw;

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

    if ( hvm_load_entry(VIRIDIAN_VCPU, h, &ctxt) != 0 )
        return -EINVAL;

    v->arch.hvm_vcpu.viridian.apic_assist.raw = ctxt.apic_assist;

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VIRIDIAN_VCPU, viridian_save_vcpu_ctxt,
                          viridian_load_vcpu_ctxt, 1, HVMSR_PER_VCPU);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
