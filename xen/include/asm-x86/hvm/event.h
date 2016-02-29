/*
 * include/asm-x86/hvm/event.h
 *
 * Arch-specific hardware virtual machine event abstractions.
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

#ifndef __ASM_X86_HVM_EVENT_H__
#define __ASM_X86_HVM_EVENT_H__

#include <xen/sched.h>
#include <xen/paging.h>
#include <public/vm_event.h>

enum hvm_event_breakpoint_type
{
    HVM_EVENT_SOFTWARE_BREAKPOINT,
    HVM_EVENT_SINGLESTEP_BREAKPOINT,
};

/*
 * Called for current VCPU on crX/MSR changes by guest.
 * The event might not fire if the client has subscribed to it in onchangeonly
 * mode, hence the bool_t return type for control register write events.
 */
bool_t hvm_event_cr(unsigned int index, unsigned long value,
                    unsigned long old);
#define hvm_event_crX(cr, new, old) \
    hvm_event_cr(VM_EVENT_X86_##cr, new, old)
void hvm_event_msr(unsigned int msr, uint64_t value);
int hvm_event_breakpoint(unsigned long rip,
                         enum hvm_event_breakpoint_type type);

#endif /* __ASM_X86_HVM_EVENT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
