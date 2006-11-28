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

enum segment {
    seg_cs,
    seg_ss,
    seg_ds,
    seg_es,
    seg_fs,
    seg_gs,
    seg_tr,
    seg_ldtr,
    seg_gdtr,
    seg_idtr
};

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
    unsigned long (*get_segment_base)(struct vcpu *v, enum segment seg);

    /* 
     * Re-set the value of CR3 that Xen runs on when handling VM exits
     */
    void (*update_host_cr3)(struct vcpu *v);

    /*
     * Update specifics of the guest state:
     * 1) TS bit in guest cr0 
     * 2) TSC offset in guest
     */
    void (*stts)(struct vcpu *v);
    void (*set_tsc_offset)(struct vcpu *v, u64 offset);

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

static inline int
hvm_paging_enabled(struct vcpu *v)
{
    return hvm_funcs.paging_enabled(v);
}

static inline int
hvm_long_mode_enabled(struct vcpu *v)
{
    return hvm_funcs.long_mode_enabled(v);
}

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

int hvm_instruction_length(unsigned long pc, int mode);

static inline void
hvm_update_host_cr3(struct vcpu *v)
{
    hvm_funcs.update_host_cr3(v);
}

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
hvm_get_segment_base(struct vcpu *v, enum segment seg)
{
    return hvm_funcs.get_segment_base(v, seg);
}

void hvm_stts(struct vcpu *v);
void hvm_set_guest_time(struct vcpu *v, u64 gtime);
void hvm_freeze_time(struct vcpu *v);
void hvm_migrate_timers(struct vcpu *v);
void hvm_do_resume(struct vcpu *v);

static inline void
hvm_init_ap_context(struct vcpu_guest_context *ctxt,
                    int vcpuid, int trampoline_vector)
{
    return hvm_funcs.init_ap_context(ctxt, vcpuid, trampoline_vector);
}

int hvm_bringup_ap(int vcpuid, int trampoline_vector);

#endif /* __ASM_X86_HVM_HVM_H__ */
