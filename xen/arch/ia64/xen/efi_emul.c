/*
 * efi_emul.c:
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
 *
 */

#include <xen/config.h>
#include <xen/compile.h>
#include <asm/pgalloc.h>
#include <asm/vcpu.h>
#include <asm/dom_fw.h>
#include <public/sched.h>

extern unsigned long translate_domain_mpaddr(unsigned long);
extern unsigned long domain_mpa_to_imva(struct domain *,unsigned long mpaddr);

// given a current domain (virtual or metaphysical) address, return the virtual address
static unsigned long
efi_translate_domain_addr(unsigned long domain_addr, IA64FAULT *fault)
{
	struct vcpu *v = current;
	unsigned long mpaddr = domain_addr;
	*fault = IA64_NO_FAULT;

	if (v->domain->arch.efi_virt_mode) {
		*fault = vcpu_tpa(v, domain_addr, &mpaddr);
		if (*fault != IA64_NO_FAULT) return 0;
	}

	return ((unsigned long) __va(translate_domain_mpaddr(mpaddr)));
}

static efi_status_t
efi_emulate_get_time(
	unsigned long tv_addr, unsigned long tc_addr,
	IA64FAULT *fault)
{
	unsigned long tv = 0, tc = 0;
	efi_status_t status;

	//printf("efi_get_time(%016lx,%016lx) called\n", tv_addr, tc_addr);
	tv = efi_translate_domain_addr(tv_addr, fault);
	if (*fault != IA64_NO_FAULT) return 0;
	if (tc_addr) {
		tc = efi_translate_domain_addr(tc_addr, fault);
		if (*fault != IA64_NO_FAULT) return 0;
	}
	//printf("efi_get_time(%016lx,%016lx) translated to xen virtual address\n", tv, tc);
	status = (*efi.get_time)((efi_time_t *) tv, (efi_time_cap_t *) tc);
	//printf("efi_get_time returns %lx\n", status);
	return status;
}

static efi_status_t
efi_emulate_set_virtual_address_map(
	unsigned long memory_map_size, unsigned long descriptor_size,
	u32 descriptor_version, efi_memory_desc_t *virtual_map)
{
	void *efi_map_start, *efi_map_end, *p;
	efi_memory_desc_t entry, *md = &entry;
	u64 efi_desc_size;

	unsigned long *vfn;
	struct domain *d = current->domain;
	efi_runtime_services_t *efi_runtime = d->arch.efi_runtime;

	if (descriptor_version != EFI_MEMDESC_VERSION) {
		printf ("efi_emulate_set_virtual_address_map: memory descriptor version unmatched\n");
		return EFI_INVALID_PARAMETER;
	}

	if (descriptor_size != sizeof(efi_memory_desc_t)) {
		printf ("efi_emulate_set_virtual_address_map: memory descriptor size unmatched\n");
		return EFI_INVALID_PARAMETER;
	}

	if (d->arch.efi_virt_mode) return EFI_UNSUPPORTED;

	efi_map_start = virtual_map;
	efi_map_end   = efi_map_start + memory_map_size;
	efi_desc_size = sizeof(efi_memory_desc_t);

	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
		if (copy_from_user(&entry, p, sizeof(efi_memory_desc_t))) {
			printf ("efi_emulate_set_virtual_address_map: copy_from_user() fault. addr=0x%p\n", p);
			return EFI_UNSUPPORTED;
		}

		/* skip over non-PAL_CODE memory descriptors; EFI_RUNTIME is included in PAL_CODE. */
                if (md->type != EFI_PAL_CODE)
                        continue;

#define EFI_HYPERCALL_PATCH_TO_VIRT(tgt,call) \
	do { \
		vfn = (unsigned long *) domain_mpa_to_imva(d, tgt); \
		*vfn++ = FW_HYPERCALL_##call##_INDEX * 16UL + md->virt_addr; \
		*vfn++ = 0; \
	} while (0)

		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_time,EFI_GET_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_time,EFI_SET_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_wakeup_time,EFI_GET_WAKEUP_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_wakeup_time,EFI_SET_WAKEUP_TIME);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_virtual_address_map,EFI_SET_VIRTUAL_ADDRESS_MAP);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_variable,EFI_GET_VARIABLE);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_next_variable,EFI_GET_NEXT_VARIABLE);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->set_variable,EFI_SET_VARIABLE);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->get_next_high_mono_count,EFI_GET_NEXT_HIGH_MONO_COUNT);
		EFI_HYPERCALL_PATCH_TO_VIRT(efi_runtime->reset_system,EFI_RESET_SYSTEM);
	}

	/* The virtual address map has been applied. */
	d->arch.efi_virt_mode = 1;

	return EFI_SUCCESS;
}

efi_status_t
efi_emulator (struct pt_regs *regs, IA64FAULT *fault)
{
	struct vcpu *v = current;
	efi_status_t status;

	*fault = IA64_NO_FAULT;

	switch (regs->r2) {
	    case FW_HYPERCALL_EFI_RESET_SYSTEM:
		printf("efi.reset_system called ");
		if (current->domain == dom0) {
			printf("(by dom0)\n ");
			(*efi.reset_system)(EFI_RESET_WARM,0,0,NULL);
		}
		else
			domain_shutdown (current->domain, SHUTDOWN_reboot);
		status = EFI_UNSUPPORTED;
		break;
	    case FW_HYPERCALL_EFI_GET_TIME:
		status = efi_emulate_get_time (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
				fault);
		break;
	    case FW_HYPERCALL_EFI_SET_VIRTUAL_ADDRESS_MAP:
		status = efi_emulate_set_virtual_address_map (
				vcpu_get_gr(v,32),
				vcpu_get_gr(v,33),
 				(u32) vcpu_get_gr(v,34),
				(efi_memory_desc_t *) vcpu_get_gr(v,35));
		break;
	    case FW_HYPERCALL_EFI_SET_TIME:
	    case FW_HYPERCALL_EFI_GET_WAKEUP_TIME:
	    case FW_HYPERCALL_EFI_SET_WAKEUP_TIME:
		// FIXME: need fixes in efi.h from 2.6.9
	    case FW_HYPERCALL_EFI_GET_VARIABLE:
		// FIXME: need fixes in efi.h from 2.6.9
	    case FW_HYPERCALL_EFI_GET_NEXT_VARIABLE:
	    case FW_HYPERCALL_EFI_SET_VARIABLE:
	    case FW_HYPERCALL_EFI_GET_NEXT_HIGH_MONO_COUNT:
		// FIXME: need fixes in efi.h from 2.6.9
		status = EFI_UNSUPPORTED;
		break;
	    default:
		printf("unknown ia64 fw hypercall %lx\n", regs->r2);
		status = EFI_UNSUPPORTED;
	}

	return status;
}
