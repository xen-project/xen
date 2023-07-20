/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/asm-x86/hvm/monitor.h
 *
 * Arch-specific hardware virtual machine monitor abstractions.
 */

#ifndef __ASM_X86_HVM_MONITOR_H__
#define __ASM_X86_HVM_MONITOR_H__

#include <public/vm_event.h>

enum hvm_monitor_debug_type
{
    HVM_MONITOR_SOFTWARE_BREAKPOINT,
    HVM_MONITOR_SINGLESTEP_BREAKPOINT,
    HVM_MONITOR_DEBUG_EXCEPTION,
};

/*
 * Called for current VCPU on crX/MSR changes by guest. Bool return signals
 * whether emulation should be postponed.
 */
bool hvm_monitor_cr(unsigned int index, unsigned long value,
                    unsigned long old);
#define hvm_monitor_crX(cr, new, old) \
                        hvm_monitor_cr(VM_EVENT_X86_##cr, new, old)
bool hvm_monitor_msr(unsigned int msr, uint64_t new_value, uint64_t old_value);
void hvm_monitor_descriptor_access(uint64_t exit_info,
                                   uint64_t vmx_exit_qualification,
                                   uint8_t descriptor, bool is_write);
int hvm_monitor_debug(unsigned long rip, enum hvm_monitor_debug_type type,
                      unsigned int trap_type, unsigned int insn_length,
                      unsigned int pending_dbg);
int hvm_monitor_cpuid(unsigned long insn_length, unsigned int leaf,
                      unsigned int subleaf);
void hvm_monitor_interrupt(unsigned int vector, unsigned int type,
                           unsigned int err, uint64_t cr2);
bool hvm_monitor_emul_unimplemented(void);

bool hvm_monitor_check_p2m(unsigned long gla, gfn_t gfn, uint32_t pfec,
                           uint16_t kind);
int hvm_monitor_vmexit(unsigned long exit_reason,
                       unsigned long exit_qualification);

int hvm_monitor_io(unsigned int port, unsigned int bytes,
                   bool in, bool str);

#endif /* __ASM_X86_HVM_MONITOR_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
