/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#include <xen/sched.h>

#define DEFINE(_sym, _val) \
    __asm__ __volatile__ ( "\n->" #_sym " %0 " #_val : : "i" _val )
#define BLANK() \
    __asm__ __volatile__ ( "\n->" : : )
#define OFFSET(_sym, _str, _mem) \
    DEFINE(_sym, offsetof(_str, _mem));

void __dummy__(void)
{
    OFFSET(XREGS_eax, struct xen_regs, eax);
    OFFSET(XREGS_ebx, struct xen_regs, ebx);
    OFFSET(XREGS_ecx, struct xen_regs, ecx);
    OFFSET(XREGS_edx, struct xen_regs, edx);
    OFFSET(XREGS_esi, struct xen_regs, esi);
    OFFSET(XREGS_edi, struct xen_regs, edi);
    OFFSET(XREGS_esp, struct xen_regs, esp);
    OFFSET(XREGS_ebp, struct xen_regs, ebp);
    OFFSET(XREGS_eip, struct xen_regs, eip);
    OFFSET(XREGS_cs, struct xen_regs, cs);
    OFFSET(XREGS_ds, struct xen_regs, ds);
    OFFSET(XREGS_es, struct xen_regs, es);
    OFFSET(XREGS_fs, struct xen_regs, fs);
    OFFSET(XREGS_gs, struct xen_regs, gs);
    OFFSET(XREGS_ss, struct xen_regs, ss);
    OFFSET(XREGS_eflags, struct xen_regs, eflags);
    OFFSET(XREGS_orig_eax, struct xen_regs, orig_eax);
    BLANK();

    OFFSET(DOMAIN_processor, struct domain, processor);
    OFFSET(DOMAIN_shared_info, struct domain, shared_info);
    OFFSET(DOMAIN_event_sel, struct domain, event_selector);
    OFFSET(DOMAIN_event_addr, struct domain, event_address);
    OFFSET(DOMAIN_failsafe_sel, struct domain, failsafe_selector);
    OFFSET(DOMAIN_failsafe_addr, struct domain, failsafe_address);
    BLANK();

    OFFSET(SHINFO_upcall_pending, shared_info_t, 
           vcpu_data[0].evtchn_upcall_pending);
    OFFSET(SHINFO_upcall_mask, shared_info_t, 
           vcpu_data[0].evtchn_upcall_mask);
    BLANK();

    OFFSET(GTB_error_code, struct guest_trap_bounce, error_code);
    OFFSET(GTB_cr2, struct guest_trap_bounce, cr2);
    OFFSET(GTB_flags, struct guest_trap_bounce, flags);
    OFFSET(GTB_cs, struct guest_trap_bounce, cs);
    OFFSET(GTB_eip, struct guest_trap_bounce, eip);
    BLANK();
}
