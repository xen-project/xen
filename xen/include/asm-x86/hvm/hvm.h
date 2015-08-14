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

#include <asm/current.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/asid.h>
#include <public/domctl.h>
#include <public/hvm/save.h>
#include <public/hvm/ioreq.h>
#include <xen/mm.h>

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

struct hvm_trap {
    int           vector;
    unsigned int  type;         /* X86_EVENTTYPE_* */
    int           error_code;   /* HVM_DELIVER_NO_ERROR_CODE if n/a */
    int           insn_len;     /* Instruction length */ 
    unsigned long cr2;          /* Only for TRAP_page_fault h/w exception */
};

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    char *name;

    /* Support Hardware-Assisted Paging? */
    int hap_supported;

    /* Necessary hardware support for PVH mode? */
    int pvh_supported;

    /* Necessary hardware support for alternate p2m's? */
    bool_t altp2m_supported;

    /* Indicate HAP capabilities. */
    int hap_capabilities;


    /*
     * Initialise/destroy HVM domain/vcpu resources
     */
    int  (*domain_initialise)(struct domain *d);
    void (*domain_destroy)(struct domain *d);
    int  (*vcpu_initialise)(struct vcpu *v);
    void (*vcpu_destroy)(struct vcpu *v);

    /* save and load hvm guest cpu context for save/restore */
    void (*save_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);
    int (*load_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);

    unsigned int (*init_msr)(void);
    void (*save_msr)(struct vcpu *, struct hvm_msr *);
    int (*load_msr)(struct vcpu *, struct hvm_msr *);

    /* Examine specifics of the guest state. */
    unsigned int (*get_interrupt_shadow)(struct vcpu *v);
    void (*set_interrupt_shadow)(struct vcpu *v, unsigned int intr_shadow);
    int (*guest_x86_mode)(struct vcpu *v);
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
    void (*update_guest_cr)(struct vcpu *v, unsigned int cr);
    void (*update_guest_efer)(struct vcpu *v);

    int  (*get_guest_pat)(struct vcpu *v, u64 *);
    int  (*set_guest_pat)(struct vcpu *v, u64);

    void (*set_tsc_offset)(struct vcpu *v, u64 offset, u64 at_tsc);

    void (*inject_trap)(struct hvm_trap *trap);

    void (*init_hypercall_page)(struct domain *d, void *hypercall_page);

    int  (*event_pending)(struct vcpu *v);

    int  (*cpu_up_prepare)(unsigned int cpu);
    void (*cpu_dead)(unsigned int cpu);

    int  (*cpu_up)(void);
    void (*cpu_down)(void);

    /* Copy up to 15 bytes from cached instruction bytes at current rIP. */
    unsigned int (*get_insn_bytes)(struct vcpu *v, uint8_t *buf);

    /* Instruction intercepts: non-void return values are X86EMUL codes. */
    void (*cpuid_intercept)(
        unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx);
    void (*wbinvd_intercept)(void);
    void (*fpu_dirty_intercept)(void);
    int (*msr_read_intercept)(unsigned int msr, uint64_t *msr_content);
    int (*msr_write_intercept)(unsigned int msr, uint64_t msr_content);
    void (*invlpg_intercept)(unsigned long vaddr);
    int (*vmfunc_intercept)(struct cpu_user_regs *regs);
    void (*handle_cd)(struct vcpu *v, unsigned long value);
    void (*set_info_guest)(struct vcpu *v);
    void (*set_rdtsc_exiting)(struct vcpu *v, bool_t);

    /* Nested HVM */
    int (*nhvm_vcpu_initialise)(struct vcpu *v);
    void (*nhvm_vcpu_destroy)(struct vcpu *v);
    int (*nhvm_vcpu_reset)(struct vcpu *v);
    int (*nhvm_vcpu_vmexit_trap)(struct vcpu *v, struct hvm_trap *trap);
    uint64_t (*nhvm_vcpu_p2m_base)(struct vcpu *v);
    bool_t (*nhvm_vmcx_guest_intercepts_trap)(struct vcpu *v,
                                              unsigned int trapnr,
                                              int errcode);

    bool_t (*nhvm_vmcx_hap_enabled)(struct vcpu *v);

    enum hvm_intblk (*nhvm_intr_blocked)(struct vcpu *v);
    void (*nhvm_domain_relinquish_resources)(struct domain *d);

    /* Virtual interrupt delivery */
    void (*update_eoi_exit_bitmap)(struct vcpu *v, u8 vector, u8 trig);
    int (*virtual_intr_delivery_enabled)(void);
    void (*process_isr)(int isr, struct vcpu *v);
    void (*deliver_posted_intr)(struct vcpu *v, u8 vector);
    void (*sync_pir_to_irr)(struct vcpu *v);
    void (*handle_eoi)(u8 vector);

    /*Walk nested p2m  */
    int (*nhvm_hap_walk_L1_p2m)(struct vcpu *v, paddr_t L2_gpa,
                                paddr_t *L1_gpa, unsigned int *page_order,
                                uint8_t *p2m_acc, bool_t access_r,
                                bool_t access_w, bool_t access_x);

    void (*hypervisor_cpuid_leaf)(uint32_t sub_idx,
                                  uint32_t *eax, uint32_t *ebx,
                                  uint32_t *ecx, uint32_t *edx);

    void (*enable_msr_exit_interception)(struct domain *d);
    bool_t (*is_singlestep_supported)(void);

    /* Alternate p2m */
    void (*altp2m_vcpu_update_p2m)(struct vcpu *v);
    void (*altp2m_vcpu_update_vmfunc_ve)(struct vcpu *v);
    bool_t (*altp2m_vcpu_emulate_ve)(struct vcpu *v);
    int (*altp2m_vcpu_emulate_vmfunc)(struct cpu_user_regs *regs);
};

extern struct hvm_function_table hvm_funcs;
extern bool_t hvm_enabled;
extern bool_t cpu_has_lmsl;
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

struct hvm_ioreq_server *hvm_select_ioreq_server(struct domain *d,
                                                 ioreq_t *p);
int hvm_send_ioreq(struct hvm_ioreq_server *s, ioreq_t *p, bool_t buffered);
unsigned int hvm_broadcast_ioreq(ioreq_t *p, bool_t buffered);

void hvm_get_guest_pat(struct vcpu *v, u64 *guest_pat);
int hvm_set_guest_pat(struct vcpu *v, u64 guest_pat);

void hvm_set_guest_tsc_fixed(struct vcpu *v, u64 guest_tsc, u64 at_tsc);
#define hvm_set_guest_tsc(v, t) hvm_set_guest_tsc_fixed(v, t, 0)
u64 hvm_get_guest_tsc_fixed(struct vcpu *v, u64 at_tsc);
#define hvm_get_guest_tsc(v) hvm_get_guest_tsc_fixed(v, 0)

void hvm_init_guest_time(struct domain *d);
void hvm_set_guest_time(struct vcpu *v, u64 guest_time);
u64 hvm_get_guest_time_fixed(struct vcpu *v, u64 at_tsc);
#define hvm_get_guest_time(v) hvm_get_guest_time_fixed(v, 0)

int vmsi_deliver(
    struct domain *d, int vector,
    uint8_t dest, uint8_t dest_mode,
    uint8_t delivery_mode, uint8_t trig_mode);
struct hvm_pirq_dpci;
void vmsi_deliver_pirq(struct domain *d, const struct hvm_pirq_dpci *);
int hvm_girq_dest_2_vcpu_id(struct domain *d, uint8_t dest, uint8_t dest_mode);

#define hvm_paging_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG))
#define hvm_wp_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[0] & X86_CR0_WP))
#define hvm_pcid_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PCIDE))
#define hvm_pae_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PAE))
#define hvm_smep_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_SMEP))
#define hvm_smap_enabled(v) \
    (hvm_paging_enabled(v) && ((v)->arch.hvm_vcpu.guest_cr[4] & X86_CR4_SMAP))
#define hvm_nx_enabled(v) \
    (!!((v)->arch.hvm_vcpu.guest_efer & EFER_NX))

/* Can we use superpages in the HAP p2m table? */
#define hvm_hap_has_1gb(d) \
    (hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_1GB)
#define hvm_hap_has_2mb(d) \
    (hvm_funcs.hap_capabilities & HVM_HAP_SUPERPAGE_2MB)

/* Can the guest use 1GB superpages in its own pagetables? */
#define hvm_pse1gb_supported(d) \
    (cpu_has_page1gb && paging_mode_hap(d))

#define hvm_long_mode_enabled(v) \
    ((v)->arch.hvm_vcpu.guest_efer & EFER_LMA)

enum hvm_intblk
hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack);

static inline int
hvm_guest_x86_mode(struct vcpu *v)
{
    ASSERT(v == current);
    return hvm_funcs.guest_x86_mode(v);
}

static inline void
hvm_update_host_cr3(struct vcpu *v)
{
    if ( hvm_funcs.update_host_cr3 )
        hvm_funcs.update_host_cr3(v);
}

static inline void hvm_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    hvm_funcs.update_guest_cr(v, cr);
}

static inline void hvm_update_guest_efer(struct vcpu *v)
{
    hvm_funcs.update_guest_efer(v);
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

void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page);

static inline void
hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    hvm_funcs.get_segment_register(v, seg, reg);
}

static inline void
hvm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    hvm_funcs.set_segment_register(v, seg, reg);
}

static inline unsigned long hvm_get_shadow_gs_base(struct vcpu *v)
{
    return hvm_funcs.get_shadow_gs_base(v);
}


#define has_hvm_params(d) \
    ((d)->arch.hvm_domain.params != NULL)

#define viridian_feature_mask(d) \
    (has_hvm_params(d) ? (d)->arch.hvm_domain.params[HVM_PARAM_VIRIDIAN] : 0)

#define is_viridian_domain(d) \
    (is_hvm_domain(d) && (viridian_feature_mask(d) & HVMPV_base_freq))

#define has_viridian_time_ref_count(d) \
    (is_viridian_domain(d) && (viridian_feature_mask(d) & HVMPV_time_ref_count))

void hvm_hypervisor_cpuid_leaf(uint32_t sub_idx,
                               uint32_t *eax, uint32_t *ebx,
                               uint32_t *ecx, uint32_t *edx);
void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx);
void hvm_migrate_timers(struct vcpu *v);
bool_t hvm_io_pending(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);
void hvm_migrate_pirqs(struct vcpu *v);

void hvm_inject_trap(struct hvm_trap *trap);
void hvm_inject_hw_exception(unsigned int trapnr, int errcode);
void hvm_inject_page_fault(int errcode, unsigned long cr2);

static inline int hvm_event_pending(struct vcpu *v)
{
    return hvm_funcs.event_pending(v);
}

/* These bits in CR4 are owned by the host. */
#define HVM_CR4_HOST_MASK (mmu_cr4_features & \
    (X86_CR4_VMXE | X86_CR4_PAE | X86_CR4_MCE))

/* These exceptions must always be intercepted. */
#define HVM_TRAP_MASK ((1U << TRAP_machine_check) | (1U << TRAP_invalid_op))

/*
 * x86 event types. This enumeration is valid for:
 *  Intel VMX: {VM_ENTRY,VM_EXIT,IDT_VECTORING}_INTR_INFO[10:8]
 *  AMD SVM: eventinj[10:8] and exitintinfo[10:8] (types 0-4 only)
 */
#define X86_EVENTTYPE_EXT_INTR         0 /* external interrupt */
#define X86_EVENTTYPE_NMI              2 /* NMI */
#define X86_EVENTTYPE_HW_EXCEPTION     3 /* hardware exception */
#define X86_EVENTTYPE_SW_INTERRUPT     4 /* software interrupt (CD nn) */
#define X86_EVENTTYPE_PRI_SW_EXCEPTION 5 /* ICEBP (F1) */
#define X86_EVENTTYPE_SW_EXCEPTION     6 /* INT3 (CC), INTO (CE) */

int hvm_event_needs_reinjection(uint8_t type, uint8_t vector);

uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2);

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable);

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
    return (hvm_funcs.get_insn_bytes ? hvm_funcs.get_insn_bytes(v, buf) : 0);
}

enum hvm_task_switch_reason { TSW_jmp, TSW_iret, TSW_call_or_int };
void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode);

enum hvm_access_type {
    hvm_access_insn_fetch,
    hvm_access_none,
    hvm_access_read,
    hvm_access_write
};
int hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    unsigned int addr_size,
    unsigned long *linear_addr);

void *hvm_map_guest_frame_rw(unsigned long gfn, bool_t permanent,
                             bool_t *writable);
void *hvm_map_guest_frame_ro(unsigned long gfn, bool_t permanent);
void hvm_unmap_guest_frame(void *p, bool_t permanent);

static inline void hvm_set_info_guest(struct vcpu *v)
{
    if ( hvm_funcs.set_info_guest )
        return hvm_funcs.set_info_guest(v);
}

int hvm_debug_op(struct vcpu *v, int32_t op);

/* Caller should pause vcpu before calling this function */
void hvm_toggle_singlestep(struct vcpu *v);

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

int hvm_hap_nested_page_fault(paddr_t gpa, unsigned long gla,
                              struct npfec npfec);

#define hvm_msr_tsc_aux(v) ({                                               \
    struct domain *__d = (v)->domain;                                       \
    (__d->arch.tsc_mode == TSC_MODE_PVRDTSCP)                               \
        ? (u32)__d->arch.incarnation : (u32)(v)->arch.hvm_vcpu.msr_tsc_aux; \
})

int hvm_x2apic_msr_read(struct vcpu *v, unsigned int msr, uint64_t *msr_content);
int hvm_x2apic_msr_write(struct vcpu *v, unsigned int msr, uint64_t msr_content);

/*
 * Nested HVM
 */

/* inject vmexit into l1 guest. l1 guest will see a VMEXIT due to
 * 'trapnr' exception.
 */ 
static inline int nhvm_vcpu_vmexit_trap(struct vcpu *v, struct hvm_trap *trap)
{
    return hvm_funcs.nhvm_vcpu_vmexit_trap(v, trap);
}

/* returns l1 guest's cr3 that points to the page table used to
 * translate l2 guest physical address to l1 guest physical address.
 */
static inline uint64_t nhvm_vcpu_p2m_base(struct vcpu *v)
{
    return hvm_funcs.nhvm_vcpu_p2m_base(v);
}

/* returns true, when l1 guest intercepts the specified trap */
static inline bool_t nhvm_vmcx_guest_intercepts_trap(struct vcpu *v,
                                                     unsigned int trap,
                                                     int errcode)
{
    return hvm_funcs.nhvm_vmcx_guest_intercepts_trap(v, trap, errcode);
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

static inline bool_t hvm_enable_msr_exit_interception(struct domain *d)
{
    if ( hvm_funcs.enable_msr_exit_interception )
    {
        hvm_funcs.enable_msr_exit_interception(d);
        return 1;
    }

    return 0;
}

static inline bool_t hvm_is_singlestep_supported(void)
{
    return (hvm_funcs.is_singlestep_supported &&
            hvm_funcs.is_singlestep_supported());
}

/* returns true if hardware supports alternate p2m's */
static inline bool_t hvm_altp2m_supported(void)
{
    return hvm_funcs.altp2m_supported;
}

#ifndef NDEBUG
/* Permit use of the Forced Emulation Prefix in HVM guests */
extern bool_t opt_hvm_fep;
#else
#define opt_hvm_fep 0
#endif

/* updates the current hardware p2m */
void altp2m_vcpu_update_p2m(struct vcpu *v);

/* updates VMCS fields related to VMFUNC and #VE */
void altp2m_vcpu_update_vmfunc_ve(struct vcpu *v);

/* emulates #VE */
bool_t altp2m_vcpu_emulate_ve(struct vcpu *v);

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
