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

/*
 * The hardware virtual machine (HVM) interface abstracts away from the
 * x86/x86_64 CPU virtualization assist specifics. Currently this interface
 * supports Intel's VT-x and AMD's SVM extensions.
 */
struct hvm_function_table {
    /*
     *  Disable HVM functionality
     */
    void (*disable)(void);

    /*
     * Initialise/destroy HVM VCPU resources
     */
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
     * 4) determine the mode the guest is running in,
     * 5) return the current guest control-register value
     * 6) return the current guest segment descriptor base
     */
    int (*paging_enabled)(struct vcpu *v);
    int (*long_mode_enabled)(struct vcpu *v);
    int (*pae_enabled)(struct vcpu *v);
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
};

extern struct hvm_function_table hvm_funcs;

/*
 * For convenience, we use short hands.
 */
static inline void
hvm_disable(void)
{
    if ( hvm_funcs.disable )
        hvm_funcs.disable();
}

int hvm_domain_initialise(struct domain *d);
void hvm_domain_destroy(struct domain *d);

int hvm_vcpu_initialise(struct vcpu *v);
void hvm_vcpu_destroy(struct vcpu *v);

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
hvm_guest_x86_mode(struct vcpu *v)
{
    return hvm_funcs.guest_x86_mode(v);
}

int hvm_instruction_length(unsigned long pc, int address_bytes);

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

void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page);

static inline unsigned long
hvm_get_guest_ctrl_reg(struct vcpu *v, unsigned int num)
{
    if ( hvm_funcs.get_guest_ctrl_reg )
        return hvm_funcs.get_guest_ctrl_reg(v, num);
    return 0;                   /* force to fail */
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

#endif /* __ASM_X86_HVM_HVM_H__ */
