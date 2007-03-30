/*
 *  linux/arch/x86_64/kernel/head64.c -- prepare to run common code
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 *
 *  Jun Nakajima <jun.nakajima@intel.com>
 *	Modified for Xen.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/module.h>

#include <asm/processor.h>
#include <asm/proto.h>
#include <asm/smp.h>
#include <asm/bootsetup.h>
#include <asm/setup.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>

unsigned long start_pfn;

/* Don't add a printk in there. printk relies on the PDA which is not initialized 
   yet. */
#if 0
static void __init clear_bss(void)
{
	memset(__bss_start, 0,
	       (unsigned long) __bss_stop - (unsigned long) __bss_start);
}
#endif

#define NEW_CL_POINTER		0x228	/* Relative to real mode data */
#define OLD_CL_MAGIC_ADDR	0x90020
#define OLD_CL_MAGIC            0xA33F
#define OLD_CL_BASE_ADDR        0x90000
#define OLD_CL_OFFSET           0x90022

extern char saved_command_line[];

static void __init copy_bootdata(char *real_mode_data)
{
#ifndef CONFIG_XEN
	int new_data;
	char * command_line;

	memcpy(x86_boot_params, real_mode_data, BOOT_PARAM_SIZE);
	new_data = *(int *) (x86_boot_params + NEW_CL_POINTER);
	if (!new_data) {
		if (OLD_CL_MAGIC != * (u16 *) OLD_CL_MAGIC_ADDR) {
			printk("so old bootloader that it does not support commandline?!\n");
			return;
		}
		new_data = OLD_CL_BASE_ADDR + * (u16 *) OLD_CL_OFFSET;
		printk("old bootloader convention, maybe loadlin?\n");
	}
	command_line = (char *) ((u64)(new_data));
	memcpy(saved_command_line, command_line, COMMAND_LINE_SIZE);
#else
	int max_cmdline;
	
	if ((max_cmdline = MAX_GUEST_CMDLINE) > COMMAND_LINE_SIZE)
		max_cmdline = COMMAND_LINE_SIZE;
	memcpy(saved_command_line, xen_start_info->cmd_line, max_cmdline);
	saved_command_line[max_cmdline-1] = '\0';
#endif
	printk("Bootdata ok (command line is %s)\n", saved_command_line);
}

static void __init setup_boot_cpu_data(void)
{
	unsigned int dummy, eax;

	/* get vendor info */
	cpuid(0, (unsigned int *)&boot_cpu_data.cpuid_level,
	      (unsigned int *)&boot_cpu_data.x86_vendor_id[0],
	      (unsigned int *)&boot_cpu_data.x86_vendor_id[8],
	      (unsigned int *)&boot_cpu_data.x86_vendor_id[4]);

	/* get cpu type */
	cpuid(1, &eax, &dummy, &dummy,
		(unsigned int *) &boot_cpu_data.x86_capability);
	boot_cpu_data.x86 = (eax >> 8) & 0xf;
	boot_cpu_data.x86_model = (eax >> 4) & 0xf;
	boot_cpu_data.x86_mask = eax & 0xf;
}

#include <xen/interface/memory.h>
unsigned long *machine_to_phys_mapping;
EXPORT_SYMBOL(machine_to_phys_mapping);
unsigned int machine_to_phys_order;
EXPORT_SYMBOL(machine_to_phys_order);

void __init x86_64_start_kernel(char * real_mode_data)
{
	struct xen_machphys_mapping mapping;
	unsigned long machine_to_phys_nr_ents;
	char *s;
	int i;

	setup_xen_features();

	xen_start_info = (struct start_info *)real_mode_data;
	if (!xen_feature(XENFEAT_auto_translated_physmap))
		phys_to_machine_mapping =
			(unsigned long *)xen_start_info->mfn_list;
	start_pfn = (__pa(xen_start_info->pt_base) >> PAGE_SHIFT) +
		xen_start_info->nr_pt_frames;

	machine_to_phys_mapping = (unsigned long *)MACH2PHYS_VIRT_START;
	machine_to_phys_nr_ents = MACH2PHYS_NR_ENTRIES;
	if (HYPERVISOR_memory_op(XENMEM_machphys_mapping, &mapping) == 0) {
		machine_to_phys_mapping = (unsigned long *)mapping.v_start;
		machine_to_phys_nr_ents = mapping.max_mfn + 1;
	}
	while ((1UL << machine_to_phys_order) < machine_to_phys_nr_ents )
		machine_to_phys_order++;

#if 0
	for (i = 0; i < 256; i++)
		set_intr_gate(i, early_idt_handler);
	asm volatile("lidt %0" :: "m" (idt_descr));
#endif

	/*
	 * This must be called really, really early:
	 */
	lockdep_init();

 	for (i = 0; i < NR_CPUS; i++)
 		cpu_pda(i) = &boot_cpu_pda[i];

	pda_init(0);
	copy_bootdata(real_mode_data);
#ifdef CONFIG_SMP
	cpu_set(0, cpu_online_map);
#endif
	s = strstr(saved_command_line, "earlyprintk=");
	if (s != NULL)
		setup_early_printk(strchr(s, '=') + 1);
#ifdef CONFIG_NUMA
	s = strstr(saved_command_line, "numa=");
	if (s != NULL)
		numa_setup(s+5);
#endif
#ifdef CONFIG_X86_IO_APIC
	if (strstr(saved_command_line, "disableapic"))
		disable_apic = 1;
#endif
	/* You need early console to see that */
	if (__pa_symbol(&_end) >= KERNEL_TEXT_SIZE)
		panic("Kernel too big for kernel mapping\n");

	setup_boot_cpu_data();
	start_kernel();
}
