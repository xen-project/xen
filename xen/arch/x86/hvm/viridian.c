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
#include <asm/hvm/support.h>
#include <public/sched.h>
#include <public/hvm/hvm_op.h>

/* Viridian MSR numbers. */
#define VIRIDIAN_MSR_GUEST_OS_ID 0x40000000
#define VIRIDIAN_MSR_HYPERCALL   0x40000001
#define VIRIDIAN_MSR_VP_INDEX    0x40000002
#define VIRIDIAN_MSR_EOI         0x40000070
#define VIRIDIAN_MSR_ICR         0x40000071
#define VIRIDIAN_MSR_TPR         0x40000072
#define VIRIDIAN_MSR_APIC_ASSIST 0x40000073

/* Viridian Hypercall Status Codes. */
#define HV_STATUS_SUCCESS                       0x0000
#define HV_STATUS_INVALID_HYPERCALL_CODE        0x0002

/* Viridian Hypercall Codes and Parameters. */
#define HvNotifyLongSpinWait    8

/* Viridian CPUID 4000003, Viridian MSR availability. */
#define CPUID3A_MSR_APIC_ACCESS (1 << 4)
#define CPUID3A_MSR_HYPERCALL   (1 << 5)
#define CPUID3A_MSR_VP_INDEX    (1 << 6)

/* Viridian CPUID 4000004, Implementation Recommendations. */
#define CPUID4A_MSR_BASED_APIC  (1 << 3)
#define CPUID4A_RELAX_TIMER_INT (1 << 5)

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
        break;
    case 4:
        /* Recommended hypercall usage. */
        if ( (d->arch.hvm_domain.viridian.guest_os_id.raw == 0) ||
             (d->arch.hvm_domain.viridian.guest_os_id.fields.os < 4) )
            break;
        *eax = (CPUID4A_MSR_BASED_APIC |
                CPUID4A_RELAX_TIMER_INT);
        *ebx = 2047; /* long spin count */
        break;
    }

    return 1;
}

static void enable_hypercall_page(void)
{
    struct domain *d = current->domain;
    unsigned long gmfn = d->arch.hvm_domain.viridian.hypercall_gpa.fields.pfn;
    unsigned long mfn = gmfn_to_mfn(d, gmfn);
    uint8_t *p;

    if ( !mfn_valid(mfn) ||
         !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
    {
        gdprintk(XENLOG_WARNING, "Bad GMFN %lx (MFN %lx)\n", gmfn, mfn);
        return;
    }

    p = map_domain_page(mfn);

    /*
     * We set the bit 31 in %eax (reserved field in the Viridian hypercall
     * calling convention) to differentiate Xen and Viridian hypercalls.
     */
    *(u8  *)(p + 0) = 0x0d; /* orl $0x80000000, %eax */
    *(u32 *)(p + 1) = 0x80000000;
    *(u8  *)(p + 5) = 0x0f; /* vmcall/vmmcall */
    *(u8  *)(p + 6) = 0x01;
    *(u8  *)(p + 7) = ((boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
                       ? 0xc1 : 0xd9);
    *(u8  *)(p + 8) = 0xc3; /* ret */
    memset(p + 9, 0xcc, PAGE_SIZE - 9); /* int3, int3, ... */

    unmap_domain_page(p);

    put_page_and_type(mfn_to_page(mfn));
}

int wrmsr_viridian_regs(uint32_t idx, uint64_t val)
{
    struct domain *d = current->domain;

    if ( !is_viridian_domain(d) )
        return 0;

    switch ( idx )
    {
    case VIRIDIAN_MSR_GUEST_OS_ID:
        perfc_incr(mshv_wrmsr_osid);
        d->arch.hvm_domain.viridian.guest_os_id.raw = val;
        gdprintk(XENLOG_INFO, "Guest os:\n");
        gdprintk(XENLOG_INFO, "\tvendor: %x\n",
               d->arch.hvm_domain.viridian.guest_os_id.fields.vendor);
        gdprintk(XENLOG_INFO, "\tos: %x\n",
               d->arch.hvm_domain.viridian.guest_os_id.fields.os);
        gdprintk(XENLOG_INFO, "\tmajor: %x\n",
               d->arch.hvm_domain.viridian.guest_os_id.fields.major);
        gdprintk(XENLOG_INFO, "\tminor: %x\n",
               d->arch.hvm_domain.viridian.guest_os_id.fields.minor);
        gdprintk(XENLOG_INFO, "\tsp: %x\n",
               d->arch.hvm_domain.viridian.guest_os_id.fields.service_pack);
        gdprintk(XENLOG_INFO, "\tbuild: %x\n",
               d->arch.hvm_domain.viridian.guest_os_id.fields.build_number);
        break;

    case VIRIDIAN_MSR_HYPERCALL:
        perfc_incr(mshv_wrmsr_hc_page);
        gdprintk(XENLOG_INFO, "Set hypercall page %"PRIx64".\n", val);
        if ( d->arch.hvm_domain.viridian.guest_os_id.raw == 0 )
            break;
        d->arch.hvm_domain.viridian.hypercall_gpa.raw = val;
        if ( d->arch.hvm_domain.viridian.hypercall_gpa.fields.enabled )
            enable_hypercall_page();
        break;

    case VIRIDIAN_MSR_VP_INDEX:
        perfc_incr(mshv_wrmsr_vp_index);
        gdprintk(XENLOG_INFO, "Set VP index %"PRIu64".\n", val);
        break;

    case VIRIDIAN_MSR_EOI:
        perfc_incr(mshv_wrmsr_eoi);
        vlapic_EOI_set(vcpu_vlapic(current));
        break;

    case VIRIDIAN_MSR_ICR: {
        u32 eax = (u32)val, edx = (u32)(val >> 32);
        struct vlapic *vlapic = vcpu_vlapic(current);
        perfc_incr(mshv_wrmsr_icr);
        eax &= ~(1 << 12);
        edx &= 0xff000000;
        vlapic_set_reg(vlapic, APIC_ICR2, edx);
        if ( vlapic_ipi(vlapic, eax, edx) == X86EMUL_OKAY )
            vlapic_set_reg(vlapic, APIC_ICR, eax);
        break;
    }

    case VIRIDIAN_MSR_TPR:
        perfc_incr(mshv_wrmsr_tpr);
        vlapic_set_reg(vcpu_vlapic(current), APIC_TASKPRI, (uint8_t)val);
        break;

    case VIRIDIAN_MSR_APIC_ASSIST:
        /*
         * We don't support the APIC assist page, and that fact is reflected in
         * our CPUID flags. However, Windows 7 build 7000 has a bug which means
         * that it doesn't recognise that, and tries to use the page anyway. We
         * therefore have to fake up just enough to keep win7 happy.
         * Fortunately, that's really easy: just setting the first four bytes
         * in the page to zero effectively disables the page again, so that's
         * what we do. Semantically, the first four bytes are supposed to be a
         * flag saying whether the guest really needs to issue an EOI. Setting
         * that flag to zero means that it must always issue one, which is what
         * we want. Once a page has been repurposed as an APIC assist page the
         * guest isn't allowed to set anything in it, so the flag remains zero
         * and all is fine. The guest is allowed to clear flags in the page,
         * but that doesn't cause us any problems.
         */
        if ( val & 1 ) /* APIC assist page enabled? */
        {
            uint32_t word = 0;
            paddr_t page_start = val & ~1ul;
            (void)hvm_copy_to_guest_phys(page_start, &word, sizeof(word));
        }
        break;

    default:
        return 0;
    }

    return 1;
}

int rdmsr_viridian_regs(uint32_t idx, uint64_t *val)
{
    struct vcpu *v = current;
    
    if ( !is_viridian_domain(v->domain) )
        return 0;

    switch ( idx )
    {
    case VIRIDIAN_MSR_GUEST_OS_ID:
        perfc_incr(mshv_rdmsr_osid);
        *val = v->domain->arch.hvm_domain.viridian.guest_os_id.raw;
        break;

    case VIRIDIAN_MSR_HYPERCALL:
        perfc_incr(mshv_rdmsr_hc_page);
        *val = v->domain->arch.hvm_domain.viridian.hypercall_gpa.raw;
        break;

    case VIRIDIAN_MSR_VP_INDEX:
        perfc_incr(mshv_rdmsr_vp_index);
        *val = v->vcpu_id;
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
#ifdef __x86_64__
    case 8:
        input.raw = regs->rcx;
        input_params_gpa = regs->rdx;
        output_params_gpa = regs->r8;
        break;
#endif
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
#ifdef __x86_64__
    case 8:
        regs->rax = output.raw;
        break;
#endif
    default:
        regs->edx = output.raw >> 32;
        regs->eax = output.raw;
        break;
    }

    return HVM_HCALL_completed;
}

static int viridian_save_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_viridian_context ctxt;

    if ( !is_viridian_domain(d) )
        return 0;

    ctxt.hypercall_gpa = d->arch.hvm_domain.viridian.hypercall_gpa.raw;
    ctxt.guest_os_id   = d->arch.hvm_domain.viridian.guest_os_id.raw;

    return (hvm_save_entry(VIRIDIAN, 0, h, &ctxt) != 0);
}

static int viridian_load_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct hvm_viridian_context ctxt;

    if ( hvm_load_entry(VIRIDIAN, h, &ctxt) != 0 )
        return -EINVAL;

    d->arch.hvm_domain.viridian.hypercall_gpa.raw = ctxt.hypercall_gpa;
    d->arch.hvm_domain.viridian.guest_os_id.raw   = ctxt.guest_os_id;

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VIRIDIAN, viridian_save_cpu_ctxt,
                          viridian_load_cpu_ctxt, 1, HVMSR_PER_DOM);
