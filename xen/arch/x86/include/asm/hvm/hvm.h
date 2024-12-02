/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hvm.h: Hardware virtual machine assist interface definitions.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 */

#ifndef __ASM_X86_HVM_HVM_H__
#define __ASM_X86_HVM_HVM_H__

#include <xen/mm.h>

#include <asm/alternative.h>
#include <asm/asm_defns.h>
#include <asm/current.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/asid.h>

struct pirq; /* needed by pi_update_irte */

#ifdef CONFIG_HVM_FEP
/* Permit use of the Forced Emulation Prefix in HVM guests */
extern bool opt_hvm_fep;
#else
#define opt_hvm_fep 0
#endif

/*
 * Results for hvm_guest_x86_mode().
 *
 * Note, some callers depend on the order of these constants.
 *
 * TODO: Rework hvm_guest_x86_mode() to avoid mixing the architectural
 * concepts of mode and operand size.
 */
#define X86_MODE_REAL  0
#define X86_MODE_VM86  1
#define X86_MODE_16BIT 2
#define X86_MODE_32BIT 4
#define X86_MODE_64BIT 8

/* Interrupt acknowledgement sources. */
enum hvm_intsrc {
    hvm_intsrc_none,
    hvm_intsrc_pic,
    hvm_intsrc_lapic,
    hvm_intsrc_nmi,
    hvm_intsrc_mce,
    hvm_intsrc_vector
};
struct hvm_intack {
    uint8_t source; /* enum hvm_intsrc */
    uint8_t vector;
};
#define hvm_intack(src, vec)   ((struct hvm_intack) { hvm_intsrc_##src, vec })
#define hvm_intack_none        hvm_intack(none, 0)
#define hvm_intack_pic(vec)    hvm_intack(pic, vec)
#define hvm_intack_lapic(vec)  hvm_intack(lapic, vec)
#define hvm_intack_nmi         hvm_intack(nmi, 2)
#define hvm_intack_mce         hvm_intack(mce, 18)
#define hvm_intack_vector(vec) hvm_intack(vector, vec)
enum hvm_intblk {
    hvm_intblk_none,      /* not blocked (deliverable) */
    hvm_intblk_shadow,    /* MOV-SS or STI shadow */
    hvm_intblk_rflags_ie, /* RFLAGS.IE == 0 */
    hvm_intblk_tpr,       /* LAPIC TPR too high */
    hvm_intblk_nmi_iret,  /* NMI blocked until IRET */
    hvm_intblk_arch,      /* SVM/VMX specific reason */
};

/* These happen to be the same as the VMX interrupt shadow definitions. */
#define HVM_INTR_SHADOW_STI    0x00000001
#define HVM_INTR_SHADOW_MOV_SS 0x00000002
#define HVM_INTR_SHADOW_SMI    0x00000004
#define HVM_INTR_SHADOW_NMI    0x00000008

#define HVM_EVENT_VECTOR_UNSET    (-1)
#define HVM_EVENT_VECTOR_UPDATING (-2)

/* update_guest_cr() flags. */
#define HVM_UPDATE_GUEST_CR3_NOFLUSH 0x00000001

struct hvm_vcpu_nonreg_state {
    union {
        struct {
            uint64_t activity_state;
            uint64_t interruptibility_info;
            uint64_t pending_dbg;
            uint64_t interrupt_status;
        } vmx;
    };
};

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    const char *name;

    struct {
        /* Indicate HAP capabilities. */
        bool hap:1,
             hap_superpage_1gb:1,
             hap_superpage_2mb:1,

             /* Altp2m capabilities */
             altp2m:1,
             singlestep:1,
            
             /* Hardware virtual interrupt delivery enable? */
             virtual_intr_delivery:1,

             /* Nested virt capabilities */
             nested_virt:1;
    } caps;

    /*
     * Initialise/destroy HVM domain/vcpu resources
     */
    int  (*domain_initialise)(struct domain *d);
    void (*domain_creation_finished)(struct domain *d);
    void (*domain_relinquish_resources)(struct domain *d);
    void (*domain_destroy)(struct domain *d);
    int  (*vcpu_initialise)(struct vcpu *v);
    void (*vcpu_destroy)(struct vcpu *v);

    /* save and load hvm guest cpu context for save/restore */
    void (*save_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);
    int (*load_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);

    /* Examine specifics of the guest state. */
    unsigned int (*get_interrupt_shadow)(struct vcpu *v);
    void (*set_interrupt_shadow)(struct vcpu *v, unsigned int intr_shadow);
    void (*get_nonreg_state)(struct vcpu *v,
                             struct hvm_vcpu_nonreg_state *nrs);
    void (*set_nonreg_state)(struct vcpu *v,
                             struct hvm_vcpu_nonreg_state *nrs);
    int (*guest_x86_mode)(struct vcpu *v);
    unsigned int (*get_cpl)(struct vcpu *v);
    void (*get_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);
    void (*set_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);

    /* 
     * Re-set the value of CR3 that Xen runs on when handling VM exits.
     */
    void (*update_host_cr3)(struct vcpu *v);

    /*
     * Called to inform HVM layer that a guest CRn or EFER has changed.
     */
    void (*update_guest_cr)(struct vcpu *v, unsigned int cr,
                            unsigned int flags);
    void (*update_guest_efer)(struct vcpu *v);

    void (*cpuid_policy_changed)(struct vcpu *v);

    void (*fpu_leave)(struct vcpu *v);

    int  (*get_guest_pat)(struct vcpu *v, uint64_t *gpat);
    int  (*set_guest_pat)(struct vcpu *v, uint64_t gpat);

    void (*set_tsc_offset)(struct vcpu *v, u64 offset, u64 at_tsc);

    void (*inject_event)(const struct x86_event *event);

    void (*init_hypercall_page)(void *ptr);

    bool (*event_pending)(const struct vcpu *v);
    bool (*get_pending_event)(struct vcpu *v, struct x86_event *info);
    void (*invlpg)(struct vcpu *v, unsigned long linear);

    int  (*cpu_up_prepare)(unsigned int cpu);
    void (*cpu_dead)(unsigned int cpu);

    int  (*cpu_up)(void);
    void (*cpu_down)(void);

    /* Copy up to 15 bytes from cached instruction bytes at current rIP. */
    unsigned int (*get_insn_bytes)(struct vcpu *v, uint8_t *buf);

    /* Instruction intercepts: non-void return values are X86EMUL codes. */
    void (*wbinvd_intercept)(void);
    void (*fpu_dirty_intercept)(void);
    int (*msr_read_intercept)(unsigned int msr, uint64_t *msr_content);
    int (*msr_write_intercept)(unsigned int msr, uint64_t msr_content);
    void (*handle_cd)(struct vcpu *v, unsigned long value);
    void (*set_info_guest)(struct vcpu *v);
    void (*set_rdtsc_exiting)(struct vcpu *v, bool enable);
    void (*set_descriptor_access_exiting)(struct vcpu *v, bool enable);

    /* Nested HVM */
    int (*nhvm_vcpu_initialise)(struct vcpu *v);
    void (*nhvm_vcpu_destroy)(struct vcpu *v);
    int (*nhvm_vcpu_reset)(struct vcpu *v);
    int (*nhvm_vcpu_vmexit_event)(struct vcpu *v, const struct x86_event *event);
    uint64_t (*nhvm_vcpu_p2m_base)(struct vcpu *v);
    bool (*nhvm_vmcx_guest_intercepts_event)(
        struct vcpu *v, unsigned int vector, int errcode);

    bool (*nhvm_vmcx_hap_enabled)(struct vcpu *v);

    enum hvm_intblk (*nhvm_intr_blocked)(struct vcpu *v);
    void (*nhvm_domain_relinquish_resources)(struct domain *d);

    /* Virtual interrupt delivery */
    void (*update_eoi_exit_bitmap)(struct vcpu *v, uint8_t vector, bool set);
    void (*process_isr)(int isr, struct vcpu *v);
    void (*deliver_posted_intr)(struct vcpu *v, u8 vector);
    void (*sync_pir_to_irr)(struct vcpu *v);
    bool (*test_pir)(const struct vcpu *v, uint8_t vector);
    void (*handle_eoi)(uint8_t vector, int isr);
    int (*pi_update_irte)(const struct vcpu *v, const struct pirq *pirq,
                          uint8_t gvec);
    void (*update_vlapic_mode)(struct vcpu *v);

    /*Walk nested p2m  */
    int (*nhvm_hap_walk_L1_p2m)(struct vcpu *v, paddr_t L2_gpa,
                                paddr_t *L1_gpa, unsigned int *page_order,
                                uint8_t *p2m_acc, struct npfec npfec);

    void (*enable_msr_interception)(struct domain *d, uint32_t msr);

    /* Alternate p2m */
    void (*altp2m_vcpu_update_p2m)(struct vcpu *v);
    void (*altp2m_vcpu_update_vmfunc_ve)(struct vcpu *v);
    bool (*altp2m_vcpu_emulate_ve)(struct vcpu *v);
    int (*altp2m_vcpu_emulate_vmfunc)(const struct cpu_user_regs *regs);

    /* vmtrace */
    int (*vmtrace_control)(struct vcpu *v, bool enable, bool reset);
    int (*vmtrace_output_position)(struct vcpu *v, uint64_t *pos);
    int (*vmtrace_set_option)(struct vcpu *v, uint64_t key, uint64_t value);
    int (*vmtrace_get_option)(struct vcpu *v, uint64_t key, uint64_t *value);
    int (*vmtrace_reset)(struct vcpu *v);

    uint64_t (*get_reg)(struct vcpu *v, unsigned int reg);
    void (*set_reg)(struct vcpu *v, unsigned int reg, uint64_t val);

    /*
     * Parameters and callbacks for hardware-assisted TSC scaling,
     * which are valid only when the hardware feature is available.
     */
    struct {
        /* number of bits of the fractional part of TSC scaling ratio */
        uint8_t  ratio_frac_bits;
        /* maximum-allowed TSC scaling ratio */
        uint64_t max_ratio;
    } tsc_scaling;
};

extern struct hvm_function_table hvm_funcs;
extern bool hvm_enabled;
extern int8_t hvm_port80_allowed;

extern const struct hvm_function_table *start_svm(void);
extern const struct hvm_function_table *start_vmx(void);

int hvm_domain_initialise(struct domain *d,
                          const struct xen_domctl_createdomain *config);
void hvm_domain_relinquish_resources(struct domain *d);
void hvm_domain_destroy(struct domain *d);

int hvm_vcpu_initialise(struct vcpu *v);
void hvm_vcpu_destroy(struct vcpu *v);
void hvm_vcpu_down(struct vcpu *v);
int hvm_vcpu_cacheattr_init(struct vcpu *v);
void hvm_vcpu_cacheattr_destroy(struct vcpu *v);
void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip);

void hvm_get_guest_pat(struct vcpu *v, uint64_t *guest_pat);
int hvm_set_guest_pat(struct vcpu *v, uint64_t guest_pat);

uint64_t hvm_get_guest_tsc_fixed(struct vcpu *v, uint64_t at_tsc);

u64 hvm_scale_tsc(const struct domain *d, u64 tsc);
u64 hvm_get_tsc_scaling_ratio(u32 gtsc_khz);

void hvm_init_guest_time(struct domain *d);
void hvm_set_guest_time(struct vcpu *v, u64 guest_time);
uint64_t hvm_get_guest_time_fixed(const struct vcpu *v, uint64_t at_tsc);

int vmsi_deliver(
    struct domain *d, int vector,
    uint8_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode);
struct hvm_pirq_dpci;
void vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *pirq_dpci);
int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode);

enum hvm_intblk
hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack);

void hvm_init_hypercall_page(struct domain *d, void *ptr);

void hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg);
void hvm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg);

void hvm_set_info_guest(struct vcpu *v);

int hvm_vmexit_cpuid(struct cpu_user_regs *regs, unsigned int inst_len);
void hvm_migrate_timers(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);
void hvm_migrate_pirq(struct hvm_pirq_dpci *pirq_dpci, const struct vcpu *v);
void hvm_migrate_pirqs(struct vcpu *v);

void hvm_inject_event(const struct x86_event *event);

int hvm_event_needs_reinjection(uint8_t type, uint8_t vector);

uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2);

void hvm_set_rdtsc_exiting(struct domain *d, bool enable);

enum hvm_task_switch_reason { TSW_jmp, TSW_iret, TSW_call_or_int };
void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode, unsigned int insn_len, unsigned int extra_eflags);

enum hvm_access_type {
    hvm_access_insn_fetch,
    hvm_access_none,
    hvm_access_read,
    hvm_access_write
};

bool hvm_vcpu_virtual_to_linear(
    struct vcpu *v,
    enum x86_segment seg,
    const struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    const struct segment_register *active_cs,
    unsigned long *linear_addr);

static inline bool hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    const struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    const struct segment_register *active_cs,
    unsigned long *linear)
{
    return hvm_vcpu_virtual_to_linear(current, seg, reg, offset, bytes,
                                      access_type, active_cs, linear);
}

void *hvm_map_guest_frame_rw(unsigned long gfn, bool permanent,
                             bool *writable);
void *hvm_map_guest_frame_ro(unsigned long gfn, bool permanent);
void hvm_unmap_guest_frame(void *p, bool permanent);
void hvm_mapped_guest_frames_mark_dirty(struct domain *d);

int hvm_debug_op(struct vcpu *v, int32_t op);

/* Caller should pause vcpu before calling this function */
void hvm_toggle_singlestep(struct vcpu *v);
void hvm_fast_singlestep(struct vcpu *v, uint16_t p2midx);

int hvm_hap_nested_page_fault(paddr_t gpa, unsigned long gla,
                              struct npfec npfec);

/* Check CR4/EFER values */
const char *hvm_efer_valid(const struct vcpu *v, uint64_t value,
                           signed int cr0_pg);
unsigned long hvm_cr4_guest_valid_bits(const struct domain *d);

int hvm_copy_context_and_params(struct domain *dst, struct domain *src);

int hvm_get_param(struct domain *d, uint32_t index, uint64_t *value);

static inline bool using_vmx(void)
{
    return IS_ENABLED(CONFIG_INTEL_VMX) && cpu_has_vmx;
}

static inline bool using_svm(void)
{
    return IS_ENABLED(CONFIG_AMD_SVM) && cpu_has_svm;
}

#ifdef CONFIG_HVM

#define hvm_get_guest_tsc(v) hvm_get_guest_tsc_fixed(v, 0)

#define hvm_tsc_scaling_supported \
    (!!hvm_funcs.tsc_scaling.ratio_frac_bits)

#define hvm_default_tsc_scaling_ratio \
    (1ULL << hvm_funcs.tsc_scaling.ratio_frac_bits)

#define hvm_tsc_scaling_ratio(d) \
    ((d)->arch.hvm.tsc_scaling_ratio)

#define hvm_get_guest_time(v) hvm_get_guest_time_fixed(v, 0)

#define hvm_paging_enabled(v) \
    (!!((v)->arch.hvm.guest_cr[0] & X86_CR0_PG))
#define hvm_wp_enabled(v) \
    (!!((v)->arch.hvm.guest_cr[0] & X86_CR0_WP))
#define hvm_pcid_enabled(v) \
    (!!((v)->arch.hvm.guest_cr[4] & X86_CR4_PCIDE))
#define hvm_pae_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm.guest_cr[4] & X86_CR4_PAE))
#define hvm_smep_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm.guest_cr[4] & X86_CR4_SMEP))
#define hvm_smap_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm.guest_cr[4] & X86_CR4_SMAP))
#define hvm_nx_enabled(v) \
    ((v)->arch.hvm.guest_efer & EFER_NXE)
#define hvm_pku_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm.guest_cr[4] & X86_CR4_PKE))
#define hvm_pks_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm.guest_cr[4] & X86_CR4_PKS))

/* Can we use superpages in the HAP p2m table? */
#define hap_has_1gb hvm_funcs.caps.hap_superpage_1gb
#define hap_has_2mb hvm_funcs.caps.hap_superpage_2mb

#define hvm_long_mode_active(v) (!!((v)->arch.hvm.guest_efer & EFER_LMA))

static inline bool hvm_has_set_descriptor_access_exiting(void)
{
    return hvm_funcs.set_descriptor_access_exiting;
}

static inline void hvm_domain_creation_finished(struct domain *d)
{
    if ( hvm_funcs.domain_creation_finished )
        alternative_vcall(hvm_funcs.domain_creation_finished, d);
}

static inline int
hvm_guest_x86_mode(struct vcpu *v)
{
    ASSERT(v == current);
    return alternative_call(hvm_funcs.guest_x86_mode, v);
}

static inline void
hvm_update_host_cr3(struct vcpu *v)
{
    if ( hvm_funcs.update_host_cr3 )
        alternative_vcall(hvm_funcs.update_host_cr3, v);
}

static inline void hvm_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    alternative_vcall(hvm_funcs.update_guest_cr, v, cr, 0);
}

static inline void hvm_update_guest_cr3(struct vcpu *v, bool noflush)
{
    unsigned int flags = noflush ? HVM_UPDATE_GUEST_CR3_NOFLUSH : 0;

    alternative_vcall(hvm_funcs.update_guest_cr, v, 3, flags);
}

static inline void hvm_update_guest_efer(struct vcpu *v)
{
    alternative_vcall(hvm_funcs.update_guest_efer, v);
}

static inline void hvm_cpuid_policy_changed(struct vcpu *v)
{
    alternative_vcall(hvm_funcs.cpuid_policy_changed, v);
}

static inline void hvm_set_tsc_offset(struct vcpu *v, uint64_t offset,
                                      uint64_t at_tsc)
{
    alternative_vcall(hvm_funcs.set_tsc_offset, v, offset, at_tsc);
}

/*
 * Called to ensure than all guest-specific mappings in a tagged TLB are 
 * flushed; does *not* flush Xen's TLB entries, and on processors without a 
 * tagged TLB it will be a noop.
 */
static inline void hvm_flush_guest_tlbs(void)
{
    if ( hvm_enabled )
        hvm_asid_flush_core();
}

static inline unsigned int
hvm_get_cpl(struct vcpu *v)
{
    return alternative_call(hvm_funcs.get_cpl, v);
}

#define has_hvm_params(d) \
    ((d)->arch.hvm.params != NULL)

#define viridian_feature_mask(d) \
    (has_hvm_params(d) ? (d)->arch.hvm.params[HVM_PARAM_VIRIDIAN] : 0)

#define is_viridian_domain(d) \
    (is_hvm_domain(d) && (viridian_feature_mask(d) & HVMPV_base_freq))

#define is_viridian_vcpu(v) \
    is_viridian_domain((v)->domain)

#define has_viridian_time_ref_count(d) \
    (is_viridian_domain(d) && (viridian_feature_mask(d) & HVMPV_time_ref_count))

#define has_viridian_apic_assist(d) \
    (is_viridian_domain(d) && (viridian_feature_mask(d) & HVMPV_apic_assist))

#define has_viridian_synic(d) \
    (is_viridian_domain(d) && (viridian_feature_mask(d) & HVMPV_synic))

static inline void hvm_inject_exception(
    unsigned int vector, unsigned int type,
    unsigned int insn_len, int error_code)
{
    struct x86_event event = {
        .vector = vector,
        .type = type,
        .insn_len = insn_len,
        .error_code = error_code,
    };

    hvm_inject_event(&event);
}

static inline void hvm_inject_hw_exception(unsigned int vector, int errcode)
{
    struct x86_event event = {
        .vector = vector,
        .type = X86_ET_HW_EXC,
        .error_code = errcode,
    };

    hvm_inject_event(&event);
}

static inline void hvm_inject_page_fault(int errcode, unsigned long cr2)
{
    struct x86_event event = {
        .vector = X86_EXC_PF,
        .type = X86_ET_HW_EXC,
        .error_code = errcode,
    };

    event.cr2 = cr2;

    hvm_inject_event(&event);
}

static inline bool hvm_event_pending(const struct vcpu *v)
{
    return alternative_call(hvm_funcs.event_pending, v);
}

static inline void hvm_invlpg(struct vcpu *v, unsigned long linear)
{
    alternative_vcall(hvm_funcs.invlpg, v, linear);
}

/* These bits in CR4 are owned by the host. */
#define HVM_CR4_HOST_MASK (mmu_cr4_features & \
    (X86_CR4_VMXE | X86_CR4_PAE | X86_CR4_MCE))

/* These exceptions must always be intercepted. */
#define HVM_TRAP_MASK ((1U << X86_EXC_DB)           | \
                       (1U << X86_EXC_AC) | \
                       (1U << X86_EXC_MC))

/* Called in boot/resume paths.  Must cope with no HVM support. */
static inline int hvm_cpu_up(void)
{
    if ( hvm_funcs.cpu_up )
        return alternative_call(hvm_funcs.cpu_up);

    return 0;
}

/* Called in shutdown paths.  Must cope with no HVM support. */
static inline void hvm_cpu_down(void)
{
    if ( hvm_funcs.cpu_down )
        alternative_vcall(hvm_funcs.cpu_down);
}

static inline unsigned int hvm_get_insn_bytes(struct vcpu *v, uint8_t *buf)
{
    return (hvm_funcs.get_insn_bytes
            ? alternative_call(hvm_funcs.get_insn_bytes, v, buf) : 0);
}

static inline void hvm_sanitize_regs_fields(struct cpu_user_regs *regs,
                                            bool compat)
{
    if ( compat )
    {
        /* Clear GPR upper halves, to counteract guests playing games. */
        regs->rbp = (uint32_t)regs->rbp;
        regs->rbx = (uint32_t)regs->rbx;
        regs->rax = (uint32_t)regs->rax;
        regs->rcx = (uint32_t)regs->rcx;
        regs->rdx = (uint32_t)regs->rdx;
        regs->rsi = (uint32_t)regs->rsi;
        regs->rdi = (uint32_t)regs->rdi;
        regs->rip = (uint32_t)regs->rip;
        regs->rflags = (uint32_t)regs->rflags;
        regs->rsp = (uint32_t)regs->rsp;
    }

#ifndef NDEBUG
    regs->error_code = 0xbeef;
    regs->entry_vector = 0xbeef;
    regs->saved_upcall_mask = 0xbf;
    regs->cs = 0xbeef;
    regs->ss = 0xbeef;
    regs->ds = 0xbeef;
    regs->es = 0xbeef;
    regs->fs = 0xbeef;
    regs->gs = 0xbeef;
#endif
}

/*
 * Nested HVM
 */

/* inject vmexit into l1 guest. l1 guest will see a VMEXIT due to
 * 'trapnr' exception.
 */ 
static inline int nhvm_vcpu_vmexit_event(
    struct vcpu *v, const struct x86_event *event)
{
    return alternative_call(hvm_funcs.nhvm_vcpu_vmexit_event, v, event);
}

/* returns l1 guest's cr3 that points to the page table used to
 * translate l2 guest physical address to l1 guest physical address.
 */
static inline uint64_t nhvm_vcpu_p2m_base(struct vcpu *v)
{
    return alternative_call(hvm_funcs.nhvm_vcpu_p2m_base, v);
}

/* returns true, when l1 guest intercepts the specified trap */
static inline bool nhvm_vmcx_guest_intercepts_event(
    struct vcpu *v, unsigned int vector, int errcode)
{
    return alternative_call(hvm_funcs.nhvm_vmcx_guest_intercepts_event, v,
                            vector, errcode);
}

/* returns true when l1 guest wants to use hap to run l2 guest */
static inline bool nhvm_vmcx_hap_enabled(struct vcpu *v)
{
    return alternative_call(hvm_funcs.nhvm_vmcx_hap_enabled, v);
}

/* interrupt */
static inline enum hvm_intblk nhvm_interrupt_blocked(struct vcpu *v)
{
    return alternative_call(hvm_funcs.nhvm_intr_blocked, v);
}

static inline int nhvm_hap_walk_L1_p2m(
    struct vcpu *v, paddr_t L2_gpa, paddr_t *L1_gpa, unsigned int *page_order,
    uint8_t *p2m_acc, struct npfec npfec)
{
    return alternative_call(hvm_funcs.nhvm_hap_walk_L1_p2m,
        v, L2_gpa, L1_gpa, page_order, p2m_acc, npfec);
}

static inline void hvm_enable_msr_interception(struct domain *d, uint32_t msr)
{
    alternative_vcall(hvm_funcs.enable_msr_interception, d, msr);
}

static inline bool hvm_is_singlestep_supported(void)
{
    return hvm_funcs.caps.singlestep;
}

static inline bool hvm_hap_supported(void)
{
    return hvm_funcs.caps.hap;
}

/* returns true if hardware supports alternate p2m's */
static inline bool hvm_altp2m_supported(void)
{
    return IS_ENABLED(CONFIG_ALTP2M) && hvm_funcs.caps.altp2m;
}

/* Returns true if we have the minimum hardware requirements for nested virt */
static inline bool hvm_nested_virt_supported(void)
{
    return hvm_funcs.caps.nested_virt;
}

/* updates the current hardware p2m */
static inline void altp2m_vcpu_update_p2m(struct vcpu *v)
{
    if ( hvm_funcs.altp2m_vcpu_update_p2m )
        alternative_vcall(hvm_funcs.altp2m_vcpu_update_p2m, v);
}

/* updates VMCS fields related to VMFUNC and #VE */
static inline void altp2m_vcpu_update_vmfunc_ve(struct vcpu *v)
{
    if ( hvm_funcs.altp2m_vcpu_update_vmfunc_ve )
        alternative_vcall(hvm_funcs.altp2m_vcpu_update_vmfunc_ve, v);
}

/* emulates #VE */
static inline bool altp2m_vcpu_emulate_ve(struct vcpu *v)
{
    if ( hvm_funcs.altp2m_vcpu_emulate_ve )
    {
        alternative_vcall(hvm_funcs.altp2m_vcpu_emulate_ve, v);
        return true;
    }
    return false;
}

static inline int hvm_vmtrace_control(struct vcpu *v, bool enable, bool reset)
{
    if ( hvm_funcs.vmtrace_control )
        return alternative_call(hvm_funcs.vmtrace_control, v, enable, reset);

    return -EOPNOTSUPP;
}

/* Returns -errno, or a boolean of whether tracing is currently active. */
static inline int hvm_vmtrace_output_position(struct vcpu *v, uint64_t *pos)
{
    if ( hvm_funcs.vmtrace_output_position )
        return alternative_call(hvm_funcs.vmtrace_output_position, v, pos);

    return -EOPNOTSUPP;
}

static inline int hvm_vmtrace_set_option(
    struct vcpu *v, uint64_t key, uint64_t value)
{
    if ( hvm_funcs.vmtrace_set_option )
        return alternative_call(hvm_funcs.vmtrace_set_option, v, key, value);

    return -EOPNOTSUPP;
}

static inline int hvm_vmtrace_get_option(
    struct vcpu *v, uint64_t key, uint64_t *value)
{
    if ( hvm_funcs.vmtrace_get_option )
        return alternative_call(hvm_funcs.vmtrace_get_option, v, key, value);

    return -EOPNOTSUPP;
}

static inline int hvm_vmtrace_reset(struct vcpu *v)
{
    if ( hvm_funcs.vmtrace_reset )
        return alternative_call(hvm_funcs.vmtrace_reset, v);

    return -EOPNOTSUPP;
}

/*
 * Accessors for registers which have per-guest-type or per-vendor locations
 * (e.g. VMCS, msr load/save lists, VMCB, VMLOAD lazy, etc).
 *
 * The caller is responsible for all auditing - these accessors do not fail,
 * but do use domain_crash() for usage errors.
 *
 * Must cope with being called in non-current context.
 */
uint64_t hvm_get_reg(struct vcpu *v, unsigned int reg);
void hvm_set_reg(struct vcpu *v, unsigned int reg, uint64_t val);

/*
 * This must be defined as a macro instead of an inline function,
 * because it uses 'struct vcpu' and 'struct domain' which have
 * not been defined yet.
 */
#define arch_vcpu_block(v) ({                                   \
    struct vcpu *v_ = (v);                                      \
    struct domain *d_ = v_->domain;                             \
    if ( is_hvm_domain(d_) && d_->arch.hvm.pi_ops.vcpu_block )  \
        d_->arch.hvm.pi_ops.vcpu_block(v_);                     \
})

static inline void hvm_get_nonreg_state(struct vcpu *v,
                                        struct hvm_vcpu_nonreg_state *nrs)
{
    if ( hvm_funcs.get_nonreg_state )
        alternative_vcall(hvm_funcs.get_nonreg_state, v, nrs);
}

static inline void hvm_set_nonreg_state(struct vcpu *v,
                                        struct hvm_vcpu_nonreg_state *nrs)
{
    if ( hvm_funcs.set_nonreg_state )
        alternative_vcall(hvm_funcs.set_nonreg_state, v, nrs);
}

static inline int hvm_pi_update_irte(const struct vcpu *v,
                                     const struct pirq *pirq, uint8_t gvec)
{
    return alternative_call(hvm_funcs.pi_update_irte, v, pirq, gvec);
}

static inline void hvm_update_vlapic_mode(struct vcpu *v)
{
    if ( hvm_funcs.update_vlapic_mode )
        alternative_vcall(hvm_funcs.update_vlapic_mode, v);
}

static inline void hvm_sync_pir_to_irr(struct vcpu *v)
{
    if ( hvm_funcs.sync_pir_to_irr )
        alternative_vcall(hvm_funcs.sync_pir_to_irr, v);
}

#else  /* CONFIG_HVM */

#define hvm_enabled false

/*
 * List of inline functions above, of which only declarations are
 * needed because DCE will kick in.
 */
int hvm_guest_x86_mode(struct vcpu *v);
void hvm_cpuid_policy_changed(struct vcpu *v);
void hvm_set_tsc_offset(struct vcpu *v, uint64_t offset, uint64_t at_tsc);

/* End of prototype list */

/* Called by code in other header  */
static inline bool hvm_is_singlestep_supported(void)
{
    return false;
}

static inline bool hvm_hap_supported(void)
{
    return false;
}

static inline bool hvm_altp2m_supported(void)
{
    return false;
}

static inline bool hvm_nested_virt_supported(void)
{
    return false;
}

static inline bool nhvm_vmcx_hap_enabled(const struct vcpu *v)
{
    ASSERT_UNREACHABLE();
    return false;
}


/* Called by common code */
static inline int hvm_cpu_up(void)
{
    return 0;
}

static inline void hvm_cpu_down(void) {}

static inline void hvm_flush_guest_tlbs(void) {}

static inline void hvm_invlpg(const struct vcpu *v, unsigned long linear)
{
    ASSERT_UNREACHABLE();
}

static inline void hvm_domain_creation_finished(struct domain *d)
{
    ASSERT_UNREACHABLE();
}

/*
 * Shadow code needs further cleanup to eliminate some HVM-only paths. For
 * now provide the stubs here but assert they will never be reached.
 */
static inline void hvm_update_host_cr3(const struct vcpu *v)
{
    ASSERT_UNREACHABLE();
}

static inline void hvm_update_guest_cr3(const struct vcpu *v, bool noflush)
{
    ASSERT_UNREACHABLE();
}

static inline unsigned int hvm_get_cpl(const struct vcpu *v)
{
    ASSERT_UNREACHABLE();
    return -1;
}

static inline bool hvm_event_pending(const struct vcpu *v)
{
    return false;
}

static inline void hvm_inject_hw_exception(unsigned int vector, int errcode)
{
    ASSERT_UNREACHABLE();
}

static inline bool hvm_has_set_descriptor_access_exiting(void)
{
    return false;
}

static inline int hvm_vmtrace_control(struct vcpu *v, bool enable, bool reset)
{
    return -EOPNOTSUPP;
}

static inline int hvm_vmtrace_output_position(struct vcpu *v, uint64_t *pos)
{
    return -EOPNOTSUPP;
}

static inline int hvm_vmtrace_set_option(
    struct vcpu *v, uint64_t key, uint64_t value)
{
    return -EOPNOTSUPP;
}

static inline int hvm_vmtrace_get_option(
    struct vcpu *v, uint64_t key, uint64_t *value)
{
    return -EOPNOTSUPP;
}

static inline uint64_t hvm_get_reg(struct vcpu *v, unsigned int reg)
{
    ASSERT_UNREACHABLE();
    return 0;
}
static inline void hvm_set_reg(struct vcpu *v, unsigned int reg, uint64_t val)
{
    ASSERT_UNREACHABLE();
}

#define is_viridian_domain(d) ((void)(d), false)
#define is_viridian_vcpu(v) ((void)(v), false)
#define has_viridian_time_ref_count(d) ((void)(d), false)
#define hvm_long_mode_active(v) ((void)(v), false)
#define hvm_get_guest_time(v) ((void)(v), 0)

#define hvm_tsc_scaling_supported false
#define hap_has_1gb false
#define hap_has_2mb false

#define hvm_paging_enabled(v) ((void)(v), false)
#define hvm_wp_enabled(v) ((void)(v), false)
#define hvm_pcid_enabled(v) ((void)(v), false)
#define hvm_pae_enabled(v) ((void)(v), false)
#define hvm_smep_enabled(v) ((void)(v), false)
#define hvm_smap_enabled(v) ((void)(v), false)
#define hvm_nx_enabled(v) ((void)(v), false)
#define hvm_pku_enabled(v) ((void)(v), false)
#define hvm_pks_enabled(v) ((void)(v), false)

#define arch_vcpu_block(v) ((void)(v))

#endif  /* CONFIG_HVM */

#endif /* __ASM_X86_HVM_HVM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
