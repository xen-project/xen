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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef __ASM_X86_HVM_HVM_H__
#define __ASM_X86_HVM_HVM_H__

#include <asm/x86_emulate.h>
#include <public/domctl.h>
#include <public/hvm/save.h>

/* 
 * Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
 * segment descriptor. It happens to match the format of an AMD SVM VMCB.
 */
typedef union segment_attributes {
    u16 bytes;
    struct
    {
        u16 type:4;    /* 0;  Bit 40-43 */
        u16 s:   1;    /* 4;  Bit 44 */
        u16 dpl: 2;    /* 5;  Bit 45-46 */
        u16 p:   1;    /* 7;  Bit 47 */
        u16 avl: 1;    /* 8;  Bit 52 */
        u16 l:   1;    /* 9;  Bit 53 */
        u16 db:  1;    /* 10; Bit 54 */
        u16 g:   1;    /* 11; Bit 55 */
    } fields;
} __attribute__ ((packed)) segment_attributes_t;

/*
 * Full state of a segment register (visible and hidden portions).
 * Again, this happens to match the format of an AMD SVM VMCB.
 */
typedef struct segment_register {
    u16        sel;
    segment_attributes_t attr;
    u32        limit;
    u64        base;
} __attribute__ ((packed)) segment_register_t;

/* Interrupt acknowledgement sources. */
enum hvm_intack {
    hvm_intack_none,
    hvm_intack_pic,
    hvm_intack_lapic,
    hvm_intack_nmi
};

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    char *name;

    /*
     * Initialise/destroy HVM domain/vcpu resources
     */
    int  (*domain_initialise)(struct domain *d);
    void (*domain_destroy)(struct domain *d);
    int  (*vcpu_initialise)(struct vcpu *v);
    void (*vcpu_destroy)(struct vcpu *v);

    /*
     * Store and load guest state:
     * 1) load/store guest register state,
     * 2) modify guest state (e.g., set debug flags).
     */
    void (*store_cpu_guest_regs)(
        struct vcpu *v, struct cpu_user_regs *r, unsigned long *crs);
    void (*load_cpu_guest_regs)(
        struct vcpu *v, struct cpu_user_regs *r);

    /* save and load hvm guest cpu context for save/restore */
    void (*save_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);
    int (*load_cpu_ctxt)(struct vcpu *v, struct hvm_hw_cpu *ctxt);

    /*
     * Examine specifics of the guest state:
     * 1) determine whether paging is enabled,
     * 2) determine whether long mode is enabled,
     * 3) determine whether PAE paging is enabled,
     * 4) determine whether NX is enabled,
     * 5) determine whether interrupts are enabled or not,
     * 6) determine the mode the guest is running in,
     * 7) return the current guest control-register value
     * 8) return the current guest segment descriptor base
     * 9) return the current guest segment descriptor
     */
    int (*paging_enabled)(struct vcpu *v);
    int (*long_mode_enabled)(struct vcpu *v);
    int (*pae_enabled)(struct vcpu *v);
    int (*nx_enabled)(struct vcpu *v);
    int (*interrupts_enabled)(struct vcpu *v, enum hvm_intack);
    int (*guest_x86_mode)(struct vcpu *v);
    unsigned long (*get_guest_ctrl_reg)(struct vcpu *v, unsigned int num);
    unsigned long (*get_segment_base)(struct vcpu *v, enum x86_segment seg);
    void (*get_segment_register)(struct vcpu *v, enum x86_segment seg,
                                 struct segment_register *reg);

    /* 
     * Re-set the value of CR3 that Xen runs on when handling VM exits
     */
    void (*update_host_cr3)(struct vcpu *v);

    /*
     * Called to inform HVM layer that a guest cr3 has changed
     */
    void (*update_guest_cr3)(struct vcpu *v);

    /*
     * Called to ensure than all guest-specific mappings in a tagged TLB
     * are flushed; does *not* flush Xen's TLB entries, and on
     * processors without a tagged TLB it will be a noop.
     */
    void (*flush_guest_tlbs)(void);

    /*
     * Reflect the virtual APIC's value in the guest's V_TPR register
     */
    void (*update_vtpr)(struct vcpu *v, unsigned long value);

    /*
     * Update specifics of the guest state:
     * 1) TS bit in guest cr0 
     * 2) TSC offset in guest
     */
    void (*stts)(struct vcpu *v);
    void (*set_tsc_offset)(struct vcpu *v, u64 offset);

    void (*inject_exception)(unsigned int trapnr, int errcode,
                             unsigned long cr2);

    void (*init_ap_context)(struct vcpu_guest_context *ctxt,
                            int vcpuid, int trampoline_vector);

    void (*init_hypercall_page)(struct domain *d, void *hypercall_page);

    int  (*event_pending)(struct vcpu *v);

    int  (*cpu_up)(void);
    void (*cpu_down)(void);
};

extern struct hvm_function_table hvm_funcs;
extern int hvm_enabled;

int hvm_domain_initialise(struct domain *d);
void hvm_domain_relinquish_resources(struct domain *d);
void hvm_domain_destroy(struct domain *d);

int hvm_vcpu_initialise(struct vcpu *v);
void hvm_vcpu_destroy(struct vcpu *v);
void hvm_vcpu_reset(struct vcpu *vcpu);

void hvm_send_assist_req(struct vcpu *v);

static inline void
hvm_store_cpu_guest_regs(
    struct vcpu *v, struct cpu_user_regs *r, unsigned long *crs)
{
    hvm_funcs.store_cpu_guest_regs(v, r, crs);
}

static inline void
hvm_load_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *r)
{
    hvm_funcs.load_cpu_guest_regs(v, r);
}

void hvm_set_guest_time(struct vcpu *v, u64 gtime);
u64 hvm_get_guest_time(struct vcpu *v);

static inline int
hvm_paging_enabled(struct vcpu *v)
{
    return hvm_funcs.paging_enabled(v);
}

#ifdef __x86_64__
static inline int
hvm_long_mode_enabled(struct vcpu *v)
{
    return hvm_funcs.long_mode_enabled(v);
}
#else
#define hvm_long_mode_enabled(v) (v,0)
#endif

static inline int
hvm_pae_enabled(struct vcpu *v)
{
    return hvm_funcs.pae_enabled(v);
}

static inline int
hvm_interrupts_enabled(struct vcpu *v, enum hvm_intack type)
{
    return hvm_funcs.interrupts_enabled(v, type);
}

static inline int
hvm_nx_enabled(struct vcpu *v)
{
    return hvm_funcs.nx_enabled(v);
}

static inline int
hvm_guest_x86_mode(struct vcpu *v)
{
    return hvm_funcs.guest_x86_mode(v);
}

int hvm_instruction_fetch(unsigned long pc, int address_bytes,
                          unsigned char *buf);

static inline void
hvm_update_host_cr3(struct vcpu *v)
{
    hvm_funcs.update_host_cr3(v);
}

static inline void
hvm_update_vtpr(struct vcpu *v, unsigned long value)
{
    hvm_funcs.update_vtpr(v, value);
}

void hvm_update_guest_cr3(struct vcpu *v, unsigned long guest_cr3);

static inline void 
hvm_flush_guest_tlbs(void)
{
    if ( hvm_enabled )
        hvm_funcs.flush_guest_tlbs();
}

void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page);

static inline unsigned long
hvm_get_guest_ctrl_reg(struct vcpu *v, unsigned int num)
{
    return hvm_funcs.get_guest_ctrl_reg(v, num);
}

static inline unsigned long
hvm_get_segment_base(struct vcpu *v, enum x86_segment seg)
{
    return hvm_funcs.get_segment_base(v, seg);
}

static inline void
hvm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                         struct segment_register *reg)
{
    hvm_funcs.get_segment_register(v, seg, reg);
}

void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx);
void hvm_stts(struct vcpu *v);
void hvm_migrate_timers(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);

static inline void
hvm_init_ap_context(struct vcpu_guest_context *ctxt,
                    int vcpuid, int trampoline_vector)
{
    return hvm_funcs.init_ap_context(ctxt, vcpuid, trampoline_vector);
}

static inline void
hvm_inject_exception(unsigned int trapnr, int errcode, unsigned long cr2)
{
    hvm_funcs.inject_exception(trapnr, errcode, cr2);
}

int hvm_bringup_ap(int vcpuid, int trampoline_vector);

static inline int hvm_event_pending(struct vcpu *v)
{
    return hvm_funcs.event_pending(v);
}

/* These reserved bits in lower 32 remain 0 after any load of CR0 */
#define HVM_CR0_GUEST_RESERVED_BITS             \
    (~((unsigned long)                          \
       (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM |  \
        X86_CR0_TS | X86_CR0_ET | X86_CR0_NE |  \
        X86_CR0_WP | X86_CR0_AM | X86_CR0_NW |  \
        X86_CR0_CD | X86_CR0_PG)))

/* These bits in CR4 are owned by the host. */
#define HVM_CR4_HOST_MASK (mmu_cr4_features & \
    (X86_CR4_VMXE | X86_CR4_PAE | X86_CR4_MCE))

/* These bits in CR4 cannot be set by the guest. */
#define HVM_CR4_GUEST_RESERVED_BITS                     \
    (~((unsigned long)                                  \
       (X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD |       \
        X86_CR4_DE  | X86_CR4_PSE | X86_CR4_PAE |       \
        X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE |       \
        X86_CR4_OSFXSR | X86_CR4_OSXMMEXCPT)))

/* These exceptions must always be intercepted. */
#define HVM_TRAP_MASK (1U << TRAP_machine_check)

/*
 * x86 event types. This enumeration is valid for:
 *  Intel VMX: {VM_ENTRY,VM_EXIT,IDT_VECTORING}_INTR_INFO[10:8]
 *  AMD SVM: eventinj[10:8] and exitintinfo[10:8] (types 0-4 only)
 */
#define X86_EVENTTYPE_EXT_INTR              0    /* external interrupt */
#define X86_EVENTTYPE_NMI                   2    /* NMI                */
#define X86_EVENTTYPE_HW_EXCEPTION          3    /* hardware exception */
#define X86_EVENTTYPE_SW_INTERRUPT          4    /* software interrupt */
#define X86_EVENTTYPE_SW_EXCEPTION          6    /* software exception */

/*
 * Need to re-inject a given event? We avoid re-injecting software exceptions
 * and interrupts because the faulting/trapping instruction can simply be
 * re-executed (neither VMX nor SVM update RIP when they VMEXIT during
 * INT3/INTO/INTn).
 */
static inline int hvm_event_needs_reinjection(uint8_t type, uint8_t vector)
{
    switch ( type )
    {
    case X86_EVENTTYPE_EXT_INTR:
    case X86_EVENTTYPE_NMI:
        return 1;
    case X86_EVENTTYPE_HW_EXCEPTION:
        /*
         * SVM uses type 3 ("HW Exception") for #OF and #BP. We explicitly
         * check for these vectors, as they are really SW Exceptions. SVM has
         * not updated RIP to point after the trapping instruction (INT3/INTO).
         */
        return (vector != 3) && (vector != 4);
    default:
        /* Software exceptions/interrupts can be re-executed (e.g., INT n). */
        break;
    }
    return 0;
}

static inline int hvm_cpu_up(void)
{
    if ( hvm_funcs.cpu_up )
        return hvm_funcs.cpu_up();
    return 1;
}

static inline void hvm_cpu_down(void)
{
    if ( hvm_funcs.cpu_down )
        hvm_funcs.cpu_down();
}

#endif /* __ASM_X86_HVM_HVM_H__ */
