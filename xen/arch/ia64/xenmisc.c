/*
 * Xen misc
 * 
 * Functions/decls that are/may be needed to link with Xen because
 * of x86 dependencies
 *
 * Copyright (C) 2004 Hewlett-Packard Co.
 *	Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <linux/config.h>
#include <xen/sched.h>
#include <linux/efi.h>
#include <asm/processor.h>
#include <xen/serial.h>
#include <asm/io.h>

efi_memory_desc_t ia64_efi_io_md;
EXPORT_SYMBOL(ia64_efi_io_md);
unsigned long wait_init_idle;
int phys_proc_id[NR_CPUS];
unsigned long loops_per_jiffy = (1<<12);	// from linux/init/main.c

unsigned int watchdog_on = 0;	// from arch/x86/nmi.c ?!?

void unw_init(void) { printf("unw_init() skipped (NEED FOR KERNEL UNWIND)\n"); }
void ia64_mca_init(void) { printf("ia64_mca_init() skipped (Machine check abort handling)\n"); }
void hpsim_setup(char **x) { printf("hpsim_setup() skipped (MAY NEED FOR CONSOLE INPUT!!!)\n"); }	

long
is_platform_hp_ski(void)
{
	int i;
	long cpuid[6];

	for (i = 0; i < 5; ++i)
		cpuid[i] = ia64_get_cpuid(i);
	if ((cpuid[0] & 0xff) != 'H') return 0;
	if ((cpuid[3] & 0xff) != 0x4) return 0;
	if (((cpuid[3] >> 8) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 16) & 0xff) != 0x0) return 0;
	if (((cpuid[3] >> 24) & 0x7) != 0x7) return 0;
	return 1;
}

long
platform_is_hp_ski(void)
{
	extern long running_on_sim;
	return running_on_sim;
}

/* calls in xen/common code that are unused on ia64 */
void synchronise_pagetables(unsigned long cpu_mask) { return; }

int grant_table_create(struct domain *d) { return 0; }
void grant_table_destroy(struct domain *d)
{
	printf("grant_table_destroy: domain_destruct not tested!!!\n");
	printf("grant_table_destroy: ensure atomic_* calls work in domain_destruct!!\n");
	dummy();
	return;
}

struct pt_regs *get_execution_context(void) { return ia64_task_regs(current); }

void cleanup_writable_pagetable(struct domain *d, int what) { return; }

///////////////////////////////
// from arch/x86/apic.c
///////////////////////////////

int reprogram_ac_timer(s_time_t timeout)
{
	return 1;
}

///////////////////////////////
// from arch/x86/dompage.c
///////////////////////////////

struct pfn_info *alloc_domheap_pages(struct domain *d, unsigned int order)
{
	printf("alloc_domheap_pages: called, not implemented\n");
}

void free_domheap_pages(struct pfn_info *pg, unsigned int order)
{
	printf("free_domheap_pages: called, not implemented\n");
}


unsigned long avail_domheap_pages(void)
{
	printf("avail_domheap_pages: called, not implemented\n");
	return 0;
}

///////////////////////////////
// from arch/x86/flushtlb.c
///////////////////////////////

u32 tlbflush_clock;
u32 tlbflush_time[NR_CPUS];

///////////////////////////////
// from arch/x86/memory.c
///////////////////////////////

void init_percpu_info(void)
{
	dummy();
    //memset(percpu_info, 0, sizeof(percpu_info));
}

void free_page_type(struct pfn_info *page, unsigned int type)
{
	dummy();
}

///////////////////////////////
// from arch/x86/pci.c
///////////////////////////////

int
pcibios_prep_mwi (struct pci_dev *dev)
{
	dummy();
}

///////////////////////////////
// from arch/x86/pci-irq.c
///////////////////////////////

void pcibios_enable_irq(struct pci_dev *dev)
{
	dummy();
}

///////////////////////////////
// from arch/ia64/pci-pc.c
///////////////////////////////

#include <xen/pci.h>

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	dummy();
	return 0;
}

int (*pci_config_read)(int seg, int bus, int dev, int fn, int reg, int len, u32 *value) = NULL;
int (*pci_config_write)(int seg, int bus, int dev, int fn, int reg, int len, u32 value) = NULL;

//struct pci_fixup pcibios_fixups[] = { { 0 } };
struct pci_fixup pcibios_fixups[] = { { 0 } };

void
pcibios_align_resource(void *data, struct resource *res,
		       unsigned long size, unsigned long align)
{
	dummy();
}

void
pcibios_update_resource(struct pci_dev *dev, struct resource *root,
			struct resource *res, int resource)
{
	dummy();
}

void __devinit  pcibios_fixup_bus(struct pci_bus *b)
{
	dummy();
}

void __init pcibios_init(void)
{
	dummy();
}

char * __devinit  pcibios_setup(char *str)
{
	dummy();
	return 0;
}

///////////////////////////////
// from arch/ia64/traps.c
///////////////////////////////

void show_registers(struct pt_regs *regs)
{
	dummy();
}	

///////////////////////////////
// from common/keyhandler.c
///////////////////////////////
void dump_pageframe_info(struct domain *d)
{
	printk("dump_pageframe_info not implemented\n");
}

///////////////////////////////
// from common/physdev.c
///////////////////////////////
void
physdev_init_dom0(struct domain *d)
{
}

int
physdev_pci_access_modify(domid_t id, int bus, int dev, int func, int enable)
{
	return -EINVAL;
}
