/*
 * Done by Dietmar Hahn <dietmar.hahn@fujitsu-siemens.com>
 *
 ****************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 ****************************************************************************
 *
 * Parts are taken from FreeBSD.
 *
 */


#include "os.h"
#include "types.h"
#include "lib.h"
#include "page.h"
#include "xen/xen.h"
#include "privop.h"
#include "xen/callback.h"
#include "ia64_cpu.h"
#include "hypervisor.h"
#include "events.h"
#include "console.h"
#include "time.h"
#include "xmalloc.h"


/* For more console boot messages. */
int bootverbose;

/*
 * This structure contains start-of-day info, such as pagetable base pointer,
 * address of the shared_info structure, and things like that.
 */
union start_info_union start_info_union;

shared_info_t *HYPERVISOR_shared_info = (shared_info_t *)XSI_BASE;

struct machine_fw machineFwG;

/* This pointer is initialized in ia64.S with the address of the boot param
 * area passed by the bootloader. */
struct xen_ia64_boot_param* ia64_boot_paramP;

struct xen_ia64_boot_param ia64BootParamG;
char boot_cmd_line[COMMAND_LINE_SIZE+1];


void
ia64_write_itr_i(ia64_pte_t* pteP, u32 reg, uint64_t vAddr,
		  uint64_t ps, uint64_t pk)
{
	/* The virtual address. */
	__asm __volatile("mov	cr.ifa=%0" :: "r"(vAddr));
	/* The page size */
	__asm __volatile("mov	cr.itir=%0;;" :: "r"((ps << IA64_ITIR_PS)|(pk << IA64_ITIR_KEY)));
	/* Put pte into instruction translation register. */ 
	__asm __volatile("itr.i	itr[%0]=%1" :: "r"(reg), "r"(*(uint64_t*)pteP));
	/* Serialization */
	__asm __volatile("srlz.i");
}

void
map_pal_code(void)
{
	ia64_pte_t pte;

	xen_set_virtual_psr_ic(0);
	memset(&pte, 0, sizeof(pte));		/* Prepare the pte */
	pte.pte_p = 1;				/* present bit */
	pte.pte_ma = PTE_MA_WB;			/* memory attribute */
	pte.pte_a = 1;				/* accessed bit */
	pte.pte_d = 1;				/* dirty bit */
	pte.pte_pl = PTE_PL_KERN;		/* privilege level */
	pte.pte_ar = PTE_AR_RWX;		/* access rights */
	pte.pte_ppn = ((uint64_t) __pa(machineFwG.ia64_pal_base)) >> 14;
	pte.pte_ed = 0;				/* exception deferral */

	/*
	 * Must purge here because a itc/dtc with the same address
	 * may be in the tlb!
	 */
	ia64_ptc_l(machineFwG.ia64_pal_base, PTE_PS_16K);
	ia64_write_itr_i(&pte, IA64_TR_PAL,
			 (uint64_t) machineFwG.ia64_pal_base, PTE_PS_16K, 0);
	xen_set_virtual_psr_ic(1);
}

/* In ivt.S */
extern char hypervisor_callback;

static void
registerCallback(void)
{
	struct callback_register event =
	{
		.type = SWAP(CALLBACKTYPE_event),
		.address = SWAP((unsigned long)&hypervisor_callback),
	};
	HYPERVISOR_callback_op(CALLBACKOP_register, &event);
}

static void
init_start_info(start_info_t* xen_start_info)
{
	/* Make a copy of the start_info structure */
	start_info.nr_pages = SWAP(xen_start_info->nr_pages);
	start_info.shared_info = SWAP(xen_start_info->shared_info);
	start_info.flags = SWAP(xen_start_info->flags);
	start_info.store_mfn = SWAP(xen_start_info->store_mfn);
	start_info.store_evtchn	= SWAP(xen_start_info->store_evtchn);
	start_info.console.domU.mfn = SWAP(xen_start_info->console.domU.mfn);
	start_info.console.domU.evtchn =
				SWAP(xen_start_info->console.domU.evtchn);
	start_info.pt_base = SWAP(xen_start_info->pt_base);
	start_info.nr_pt_frames	= SWAP(xen_start_info->nr_pt_frames);
	start_info.mfn_list = SWAP(xen_start_info->mfn_list);
	start_info.mod_start = SWAP(xen_start_info->mod_start);
	start_info.mod_len = SWAP(xen_start_info->mod_len);
}

static void
init_boot_params(void)
{
	ia64BootParamG.command_line = SWAP(ia64_boot_paramP->command_line);
	ia64BootParamG.efi_systab = SWAP(ia64_boot_paramP->efi_systab);
	ia64BootParamG.efi_memmap = SWAP(ia64_boot_paramP->efi_memmap);
	ia64BootParamG.efi_memmap_size =
				SWAP(ia64_boot_paramP->efi_memmap_size);
	ia64BootParamG.efi_memdesc_size	=
				SWAP(ia64_boot_paramP->efi_memdesc_size);
	ia64BootParamG.efi_memdesc_version =
				SWAP(ia64_boot_paramP->efi_memdesc_version);
	ia64BootParamG.console_info.num_cols =
				SWAP(ia64_boot_paramP->console_info.num_cols);
	ia64BootParamG.console_info.num_rows =
				SWAP(ia64_boot_paramP->console_info.num_rows);
	ia64BootParamG.console_info.orig_x =
				SWAP(ia64_boot_paramP->console_info.orig_x);
	ia64BootParamG.console_info.orig_y =
				SWAP(ia64_boot_paramP->console_info.orig_y);
	ia64BootParamG.fpswa = SWAP(ia64_boot_paramP->fpswa);
	ia64BootParamG.initrd_start = SWAP(ia64_boot_paramP->initrd_start);
	ia64BootParamG.initrd_size = SWAP(ia64_boot_paramP->initrd_size);
	ia64BootParamG.domain_start = SWAP(ia64_boot_paramP->domain_start);
	ia64BootParamG.domain_size = SWAP(ia64_boot_paramP->domain_size);

	/*
	 * Copy and parse the boot command line.
	 * Currently only a check of bootverbose is done.
	 */
	memset(boot_cmd_line, 0, sizeof(boot_cmd_line));
	strncpy(boot_cmd_line,
		(char*)__va(ia64BootParamG.command_line), COMMAND_LINE_SIZE);
	boot_cmd_line[COMMAND_LINE_SIZE - 1] = '\0';

	/* Look for bootverbose. */
	if (strstr(boot_cmd_line, "bootverbose"))
		bootverbose = 1;
}

void
arch_init(start_info_t *si)
{
	efi_time_t tm;
	static int initialized;

	if (initialized)
		return;

	init_start_info(si);

	init_boot_params();

	init_efi();

	map_pal_code();

	ia64_sal_init(machineFwG.ia64_sal_tableP);

	if (efi_get_time(&tm)) {
		printk("EFI-SystemTime: %d.%d.%d   %d:%d:%d",
		       tm.Day, tm.Month, tm.Year,
		       tm.Hour, tm.Minute, tm.Second);

		if (tm.TimeZone == EFI_UNSPECIFIED_TIMEZONE)
			printk("   Timezone not specified!\n");
		else
			printk("   TimeZone: %d Daylight: 0x%x\n",
			       tm.TimeZone, tm.Daylight);
	} else 
		printk("efi_get_time() failed\n");

	registerCallback();
	initialized = 1;
}

void
arch_print_info(void)
{
	int major, minor;

	minor = HYPERVISOR_xen_version(XENVER_version, 0);
	major = minor >> 16;
	minor &= ~0xffffffff;
	printk("Running on Xen version: %d.%d\n", major, minor);
	printk("machine addr of shared_info_t  : 0x%lx\n",
	       start_info.shared_info);
	printk("machine page number of shared page: 0x%lx\n",
	       start_info.store_mfn);
	printk("evtchn for store communication : %d\n",
	       start_info.store_evtchn);
	printk("MACHINE address of console page: 0x%lx\n",
	       start_info.console.domU.mfn);
	printk("evtchn for console messages    : %d\n",
	       start_info.console.domU.evtchn);
	printk("xen_guest_cmdline              : %s\n", boot_cmd_line);
}
