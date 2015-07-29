/*
 * event.h: Hardware virtual machine assist events.
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

/*
 * Called for current VCPU on crX/MSR changes by guest.
 * The event might not fire if the client has subscribed to it in onchangeonly
 * mode, hence the bool_t return type for control register write events.
 */
bool_t hvm_event_cr(unsigned int index, unsigned long value,
                    unsigned long old);
#define hvm_event_crX(what, new, old) \
    hvm_event_cr(VM_EVENT_X86_##what, new, old)
void hvm_event_msr(unsigned int msr, uint64_t value);
/* Called for current VCPU: returns -1 if no listener */
int hvm_event_int3(unsigned long gla);
int hvm_event_single_step(unsigned long gla);
void hvm_event_guest_request(void);

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
