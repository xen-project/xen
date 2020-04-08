/*
 * hvm.h: Hardware virtual machine assist interface definitions.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
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

#ifndef __ASM_X86_HVM_HVM_H__
#define __ASM_X86_HVM_HVM_H__

#include <asm/alternative.h>
#include <asm/asm_defns.h>
#include <asm/current.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/asid.h>

#ifdef CONFIG_HVM_FEP
/* Permit use of the Forced Emulation Prefix in HVM guests */
extern bool_t opt_hvm_fep;
#else
#define opt_hvm_fep 0
#endif

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

/*
 * HAP super page capabilities:
 * bit0: if 2MB super page is allowed?
 * bit1: if 1GB super page is allowed?
 */
#define HVM_HAP_SUPERPAGE_2MB   0x00000001
#define HVM_HAP_SUPERPAGE_1GB   0x00000002

#define HVM_EVENT_VECTOR_UNSET    (-1)
#define HVM_EVENT_VECTOR_UPDATING (-2)

/* update_guest_cr() flags. */
#define HVM_UPDATE_GUEST_CR3_NOFLUSH 0x00000001

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    char *name;

    /* Support Hardware-Assisted Paging? */
    bool_t hap_supported;

    /* Necessary hardware support for alternate p2m's? */
    bool altp2m_supported;

    /* Hardware virtual interrupt delivery enable? */
    bool virtual_intr_delivery_enabled;

    /* Indicate HAP capabilities. */
    unsigned int hap_capabilities;

    /*
     * Initialise/destroy HVM domain/vcpu resources
     */
    int  (*domain_initialise)(struct domain *d);
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
    int (*guest_x86_mode)(struct vcpu *v);
    unsigned int (*get_cpl)(struct vcpu *v);
    void (*get_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);
    void (*set_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);
    unsigned long (*get_shadow_gs_base)(struct vcpu *v);

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

    int  (*get_guest_pat)(struct vcpu *v, u64 *);
    int  (*set_guest_pat)(struct vcpu *v, u64);

    bool (*get_guest_bndcfgs)(struct vcpu *v, u64 *);
    bool (*set_guest_bndcfgs)(struct vcpu *v, u64);

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
    void (*set_rdtsc_exiting)(struct vcpu *v, bool_t);
    void (*set_descriptor_access_exiting)(struct vcpu *v, bool);

    /* Nested HVM */
    int (*nhvm_vcpu_initialise)(struct vcpu *v);
    void (*nhvm_vcpu_destroy)(struct vcpu *v);
    int (*nhvm_vcpu_reset)(struct vcpu *v);
    int (*nhvm_vcpu_vmexit_event)(struct vcpu *v, const struct x86_event *event);
    uint64_t (*nhvm_vcpu_p2m_base)(struct vcpu *v);
    bool_t (*nhvm_vmcx_guest_intercepts_event)(
        struct vcpu *v, unsigned int vector, int errcode);

    bool_t (*nhvm_vmcx_hap_enabled)(struct vcpu *v);

    enum hvm_intblk (*nhvm_intr_blocked)(struct vcpu *v);
    void (*nhvm_domain_relinquish_resources)(struct domain *d);

    /* Virtual interrupt delivery */
    void (*update_eoi_exit_bitmap)(struct vcpu *v, u8 vector, u8 trig);
    void (*process_isr)(int isr, struct vcpu *v);
    void (*deliver_posted_intr)(struct vcpu *v, u8 vector);
    void (*sync_pir_to_irr)(struct vcpu *v);
    bool (*test_pir)(const struct vcpu *v, uint8_t vector);
    void (*handle_eoi)(uint8_t vector, int isr);

    /*Walk nested p2m  */
    int (*nhvm_hap_walk_L1_p2m)(struct vcpu *v, paddr_t L2_gpa,
                                paddr_t *L1_gpa, unsigned int *page_order,
                                uint8_t *p2m_acc, bool_t access_r,
                                bool_t access_w, bool_t access_x);

    void (*enable_msr_interception)(struct domain *d, uint32_t msr);
    bool_t (*is_singlestep_supported)(void);

    /* Alternate p2m */
    void (*altp2m_vcpu_update_p2m)(struct vcpu *v);
    void (*altp2m_vcpu_update_vmfunc_ve)(struct vcpu *v);
    bool_t (*altp2m_vcpu_emulate_ve)(struct vcpu *v);
    int (*altp2m_vcpu_emulate_vmfunc)(const struct cpu_user_regs *regs);

    /*
     * Parameters and callbacks for hardware-assisted TSC scaling,
     * which are valid only when the hardware feature is available.
     */
    struct {
        /* number of bits of the fractional part of TSC scaling ratio */
        uint8_t  ratio_frac_bits;
        /* maximum-allowed TSC scaling ratio */
        uint64_t max_ratio;

        /* Architecture function to setup TSC scaling ratio */
        void (*setup)(struct vcpu *v);
    } tsc_scaling;
};

extern struct hvm_function_table hvm_funcs;
extern bool_t hvm_enabled;
extern s8 hvm_port80_allowed;

extern const struct hvm_function_table *start_svm(void);
extern const struct hvm_function_table *start_vmx(void);

int hvm_domain_initialise(struct domain *d);
void hvm_domain_relinquish_resources(struct domain *d);
void hvm_domain_destroy(struct domain *d);

int hvm_vcpu_initialise(struct vcpu *v);
void hvm_vcpu_destroy(struct vcpu *v);
void hvm_vcpu_down(struct vcpu *v);
int hvm_vcpu_cacheattr_init(struct vcpu *v);
void hvm_vcpu_cacheattr_destroy(struct vcpu *v);
void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip);

void hvm_get_guest_pat(struct vcpu *v, u64 *guest_pat);
int hvm_set_guest_pat(struct vcpu *v, u64 guest_pat);

u64 hvm_get_guest_tsc_fixed(struct vcpu *v, u64 at_tsc);

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
void vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *);
int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode);

enum hvm_intblk
hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack);

void hvm_init_hypercall_page(struct domain *d, void *ptr);

void hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg);
void hvm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                              struct segment_register *reg);

bool hvm_set_guest_bndcfgs(struct vcpu *v, u64 val);

int hvm_vmexit_cpuid(struct cpu_user_regs *regs, unsigned int inst_len);
void hvm_migrate_timers(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);
void hvm_migrate_pirq(struct hvm_pirq_dpci *pirq_dpci, const struct vcpu *v);
void hvm_migrate_pirqs(struct vcpu *v);

void hvm_inject_event(const struct x86_event *event);

int hvm_event_needs_reinjection(uint8_t type, uint8_t vector);

uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2);

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable);

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
bool_t hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    const struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    const struct segment_register *active_cs,
    unsigned long *linear_addr);

void *hvm_map_guest_frame_rw(unsigned long gfn, bool_t permanent,
                             bool_t *writable);
void *hvm_map_guest_frame_ro(unsigned long gfn, bool_t permanent);
void hvm_unmap_guest_frame(void *p, bool_t permanent);
void hvm_mapped_guest_frames_mark_dirty(struct domain *);

int hvm_debug_op(struct vcpu *v, int32_t op);

/* Caller should pause vcpu before calling this function */
void hvm_toggle_singlestep(struct vcpu *v);
void hvm_fast_singlestep(struct vcpu *v, uint16_t p2midx);

struct npfec;
int hvm_hap_nested_page_fault(paddr_t gpa, unsigned long gla,
                              struct npfec npfec);

/* Check CR4/EFER values */
const char *hvm_efer_valid(const struct vcpu *v, uint64_t value,
                           signed int cr0_pg);
unsigned long hvm_cr4_guest_valid_bits(const struct domain *d, bool restore);

int hvm_copy_context_and_params(struct domain *src, struct domain *dst);

int hvm_get_param(struct domain *d, uint32_t index, uint64_t *value);

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
    ((v)->arch.hvm.guest_efer & EFER_NX)
#define hvm_pku_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm.guest_cr[4] & X86_CR4_PKE))

/* Can we use superpages in the HAP p2m table? */
#define hap_has_1gb (!!(hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_1GB))
#define hap_has_2mb (!!(hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_2MB))

#define hvm_long_mode_active(v) (!!((v)->arch.hvm.guest_efer & EFER_LMA))

static inline bool hvm_has_set_descriptor_access_exiting(void)
{
    return hvm_funcs.set_descriptor_access_exiting;
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

static inline unsigned long hvm_get_shadow_gs_base(struct vcpu *v)
{
    return alternative_call(hvm_funcs.get_shadow_gs_base, v);
}

static inline bool hvm_get_guest_bndcfgs(struct vcpu *v, u64 *val)
{
    return hvm_funcs.get_guest_bndcfgs &&
           alternative_call(hvm_funcs.get_guest_bndcfgs, v, val);
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
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode,
    };

    hvm_inject_event(&event);
}

static inline void hvm_inject_page_fault(int errcode, unsigned long cr2)
{
    struct x86_event event = {
        .vector = TRAP_page_fault,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode,
        .cr2 = cr2,
    };

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
#define HVM_TRAP_MASK ((1U << TRAP_debug)           | \
                       (1U << TRAP_alignment_check) | \
                       (1U << TRAP_machine_check))

static inline int hvm_cpu_up(void)
{
    return (hvm_funcs.cpu_up ? hvm_funcs.cpu_up() : 0);
}

static inline void hvm_cpu_down(void)
{
    if ( hvm_funcs.cpu_down )
        hvm_funcs.cpu_down();
}

static inline unsigned int hvm_get_insn_bytes(struct vcpu *v, uint8_t *buf)
{
    return (hvm_funcs.get_insn_bytes
            ? alternative_call(hvm_funcs.get_insn_bytes, v, buf) : 0);
}

static inline void hvm_set_info_guest(struct vcpu *v)
{
    if ( hvm_funcs.set_info_guest )
        alternative_vcall(hvm_funcs.set_info_guest, v);
}

static inline void hvm_invalidate_regs_fields(struct cpu_user_regs *regs)
{
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
    return hvm_funcs.nhvm_vcpu_vmexit_event(v, event);
}

/* returns l1 guest's cr3 that points to the page table used to
 * translate l2 guest physical address to l1 guest physical address.
 */
static inline uint64_t nhvm_vcpu_p2m_base(struct vcpu *v)
{
    return hvm_funcs.nhvm_vcpu_p2m_base(v);
}

/* returns true, when l1 guest intercepts the specified trap */
static inline bool_t nhvm_vmcx_guest_intercepts_event(
    struct vcpu *v, unsigned int vector, int errcode)
{
    return hvm_funcs.nhvm_vmcx_guest_intercepts_event(v, vector, errcode);
}

/* returns true when l1 guest wants to use hap to run l2 guest */
static inline bool_t nhvm_vmcx_hap_enabled(struct vcpu *v)
{
    return hvm_funcs.nhvm_vmcx_hap_enabled(v);
}

/* interrupt */
static inline enum hvm_intblk nhvm_interrupt_blocked(struct vcpu *v)
{
    return hvm_funcs.nhvm_intr_blocked(v);
}

static inline bool_t hvm_enable_msr_interception(struct domain *d, uint32_t msr)
{
    if ( hvm_funcs.enable_msr_interception )
    {
        hvm_funcs.enable_msr_interception(d, msr);
        return 1;
    }

    return 0;
}

static inline bool_t hvm_is_singlestep_supported(void)
{
    return (hvm_funcs.is_singlestep_supported &&
            hvm_funcs.is_singlestep_supported());
}

static inline bool hvm_hap_supported(void)
{
    return hvm_funcs.hap_supported;
}

/* returns true if hardware supports alternate p2m's */
static inline bool hvm_altp2m_supported(void)
{
    return hvm_funcs.altp2m_supported;
}

/* updates the current hardware p2m */
static inline void altp2m_vcpu_update_p2m(struct vcpu *v)
{
    if ( hvm_funcs.altp2m_vcpu_update_p2m )
        hvm_funcs.altp2m_vcpu_update_p2m(v);
}

/* updates VMCS fields related to VMFUNC and #VE */
static inline void altp2m_vcpu_update_vmfunc_ve(struct vcpu *v)
{
    if ( hvm_funcs.altp2m_vcpu_update_vmfunc_ve )
        hvm_funcs.altp2m_vcpu_update_vmfunc_ve(v);
}

/* emulates #VE */
static inline bool altp2m_vcpu_emulate_ve(struct vcpu *v)
{
    if ( hvm_funcs.altp2m_vcpu_emulate_ve )
    {
        hvm_funcs.altp2m_vcpu_emulate_ve(v);
        return true;
    }
    return false;
}

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

#else  /* CONFIG_HVM */

#define hvm_enabled false

/*
 * List of inline functions above, of which only declarations are
 * needed because DCE will kick in.
 */
int hvm_guest_x86_mode(struct vcpu *v);
unsigned long hvm_get_shadow_gs_base(struct vcpu *v);
void hvm_set_info_guest(struct vcpu *v);
void hvm_cpuid_policy_changed(struct vcpu *v);
void hvm_set_tsc_offset(struct vcpu *v, uint64_t offset, uint64_t at_tsc);
bool hvm_get_guest_bndcfgs(struct vcpu *v, uint64_t *val);

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
