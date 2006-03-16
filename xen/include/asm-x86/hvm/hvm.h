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
     * Initialize/relinguish HVM guest resources
     */
    int  (*initialize_guest_resources)(struct vcpu *v);
    void (*relinquish_guest_resources)(struct domain *d);

    /*
     * Store and load guest state:
     * 1) load/store guest register state,
     * 2) load/store segment state (x86_64 only),
     * 3) load/store msr register state (x86_64 only),
     * 4) store guest control register state (used for panic dumps),
     * 5) modify guest state (e.g., set debug flags).
     */
    void (*store_cpu_guest_regs)(struct vcpu *v, struct cpu_user_regs *r);
    void (*load_cpu_guest_regs)(struct vcpu *v, struct cpu_user_regs *r);
#ifdef __x86_64__
    void (*save_segments)(struct vcpu *v);
    void (*load_msrs)(void);
    void (*restore_msrs)(struct vcpu *v);
#endif
    void (*store_cpu_guest_ctrl_regs)(struct vcpu *v, unsigned long crs[8]);
    void (*modify_guest_state)(struct vcpu *v);

    /*
     * Examine specifics of the guest state:
     * 1) determine whether the guest is in real or vm8086 mode,
     * 2) determine whether paging is enabled,
     * 3) return the length of the instruction that caused an exit.
     * 4) return the current guest control-register value
     */
    int (*realmode)(struct vcpu *v);
    int (*paging_enabled)(struct vcpu *v);
    int (*instruction_length)(struct vcpu *v);
    unsigned long (*get_guest_ctrl_reg)(struct vcpu *v, unsigned int num);

    void (*init_ap_context)(struct vcpu_guest_context *ctxt,
                            int vcpuid, int trampoline_vector);
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

static inline int
hvm_initialize_guest_resources(struct vcpu *v)
{
    if ( hvm_funcs.initialize_guest_resources )
        return hvm_funcs.initialize_guest_resources(v);
    return 0;
}

static inline void
hvm_relinquish_guest_resources(struct domain *d)
{
    if (hvm_funcs.relinquish_guest_resources)
        hvm_funcs.relinquish_guest_resources(d);
}

static inline void
hvm_store_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *r)
{
    hvm_funcs.store_cpu_guest_regs(v, r);
}

static inline void
hvm_load_cpu_guest_regs(struct vcpu *v, struct cpu_user_regs *r)
{
    hvm_funcs.load_cpu_guest_regs(v, r);
}

#ifdef __x86_64__
static inline void
hvm_save_segments(struct vcpu *v)
{
    if (hvm_funcs.save_segments)
        hvm_funcs.save_segments(v);
}

static inline void
hvm_load_msrs(void)
{
    if (hvm_funcs.load_msrs)
        hvm_funcs.load_msrs();
}

static inline void
hvm_restore_msrs(struct vcpu *v)
{
    if (hvm_funcs.restore_msrs)
        hvm_funcs.restore_msrs(v);
}
#else
#define hvm_save_segments(v)    ((void)0)
#define hvm_load_msrs(v)        ((void)0)
#define hvm_restore_msrs(v)     ((void)0)
#endif /* __x86_64__ */

static inline void
hvm_store_cpu_guest_ctrl_regs(struct vcpu *v, unsigned long crs[8])
{
    hvm_funcs.store_cpu_guest_ctrl_regs(v, crs);
}

static inline void
hvm_modify_guest_state(struct vcpu *v)
{
    hvm_funcs.modify_guest_state(v);
}

static inline int
hvm_realmode(struct vcpu *v)
{
    return hvm_funcs.realmode(v);
}

static inline int
hvm_paging_enabled(struct vcpu *v)
{
    return hvm_funcs.paging_enabled(v);
}

static inline int
hvm_instruction_length(struct vcpu *v)
{
    return hvm_funcs.instruction_length(v);
}

static inline unsigned long
hvm_get_guest_ctrl_reg(struct vcpu *v, unsigned int num)
{
    if ( hvm_funcs.get_guest_ctrl_reg )
        return hvm_funcs.get_guest_ctrl_reg(v, num);
    return 0;                   /* force to fail */
}

static inline void
hvm_init_ap_context(struct vcpu_guest_context *ctxt,
                    int vcpuid, int trampoline_vector)
{
    return hvm_funcs.init_ap_context(ctxt, vcpuid, trampoline_vector);
}

extern int hvm_bringup_ap(int vcpuid, int trampoline_vector);

#endif /* __ASM_X86_HVM_HVM_H__ */
