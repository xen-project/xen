/*
 * include/asm-x86/hvm/monitor.h
 *
 * Arch-specific hardware virtual machine monitor abstractions.
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
 * Called for current VCPU on crX/MSR changes by guest.
 * The event might not fire if the client has subscribed to it in onchangeonly
 * mode, hence the bool return type for control register write events.
 */
bool hvm_monitor_cr(unsigned int index, unsigned long value,
                    unsigned long old);
#define hvm_monitor_crX(cr, new, old) \
                        hvm_monitor_cr(VM_EVENT_X86_##cr, new, old)
void hvm_monitor_msr(unsigned int msr, uint64_t value, uint64_t old_value);
void hvm_monitor_descriptor_access(uint64_t exit_info,
                                   uint64_t vmx_exit_qualification,
                                   uint8_t descriptor, bool is_write);
int hvm_monitor_debug(unsigned long rip, enum hvm_monitor_debug_type type,
                      unsigned long trap_type, unsigned long insn_length);
int hvm_monitor_cpuid(unsigned long insn_length, unsigned int leaf,
                      unsigned int subleaf);
void hvm_monitor_interrupt(unsigned int vector, unsigned int type,
                           unsigned int err, uint64_t cr2);
bool hvm_monitor_emul_unimplemented(void);

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
