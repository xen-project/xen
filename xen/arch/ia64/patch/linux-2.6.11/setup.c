 setup.c |   72 +++++++++++++++++++++++++++++++++++++++++++++++++++-------------
 1 files changed, 58 insertions(+), 14 deletions(-)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/setup.c
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/setup.c	2005-04-07 17:44:13.294980153 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/setup.c	2005-04-07 17:46:37.157717072 -0500
@@ -21,6 +21,9 @@
 #include <linux/init.h>
 
 #include <linux/acpi.h>
+#ifdef XEN
+#include <xen/sched.h>
+#endif
 #include <linux/bootmem.h>
 #include <linux/console.h>
 #include <linux/delay.h>
@@ -30,13 +33,17 @@
 #include <linux/seq_file.h>
 #include <linux/string.h>
 #include <linux/threads.h>
+#ifndef XEN
 #include <linux/tty.h>
 #include <linux/serial.h>
 #include <linux/serial_core.h>
+#endif
 #include <linux/efi.h>
 #include <linux/initrd.h>
 
+#ifndef XEN
 #include <asm/ia32.h>
+#endif
 #include <asm/machvec.h>
 #include <asm/mca.h>
 #include <asm/meminit.h>
@@ -51,6 +58,12 @@
 #include <asm/smp.h>
 #include <asm/system.h>
 #include <asm/unistd.h>
+#ifdef XEN
+#include <linux/mm.h>
+#include <asm/mmu_context.h>
+extern unsigned long loops_per_jiffy;		// from linux/init/main.c
+char saved_command_line[COMMAND_LINE_SIZE];	// from linux/init/main.c
+#endif
 
 #if defined(CONFIG_SMP) && (IA64_CPU_SIZE > PAGE_SIZE)
 # error "struct cpuinfo_ia64 too big!"
@@ -66,7 +79,9 @@ DEFINE_PER_CPU(unsigned long, local_per_
 DEFINE_PER_CPU(unsigned long, ia64_phys_stacked_size_p8);
 unsigned long ia64_cycles_per_usec;
 struct ia64_boot_param *ia64_boot_param;
+#ifndef XEN
 struct screen_info screen_info;
+#endif
 
 unsigned long ia64_max_cacheline_size;
 unsigned long ia64_iobase;	/* virtual address for I/O accesses */
@@ -95,7 +110,6 @@ EXPORT_SYMBOL(ia64_max_iommu_merge_mask)
 struct rsvd_region rsvd_region[IA64_MAX_RSVD_REGIONS + 1];
 int num_rsvd_regions;
 
-
 /*
  * Filter incoming memory segments based on the primitive map created from the boot
  * parameters. Segments contained in the map are removed from the memory ranges. A
@@ -125,9 +139,12 @@ filter_rsvd_memory (unsigned long start,
 	for (i = 0; i < num_rsvd_regions; ++i) {
 		range_start = max(start, prev_start);
 		range_end   = min(end, rsvd_region[i].start);
-
-		if (range_start < range_end)
-			call_pernode_memory(__pa(range_start), range_end - range_start, func);
+		/* init_boot_pages requires "ps, pe" */
+		if (range_start < range_end) {
+			printk("Init boot pages: 0x%lx -> 0x%lx.\n",
+				__pa(range_start), __pa(range_end));
+			(*func)(__pa(range_start), __pa(range_end), 0);
+		}
 
 		/* nothing more available in this segment */
 		if (range_end == end) return 0;
@@ -184,17 +201,17 @@ reserve_memory (void)
 				+ strlen(__va(ia64_boot_param->command_line)) + 1);
 	n++;
 
+	/* Reserve xen image/bitmap/xen-heap */
 	rsvd_region[n].start = (unsigned long) ia64_imva((void *)KERNEL_START);
-	rsvd_region[n].end   = (unsigned long) ia64_imva(_end);
+	rsvd_region[n].end   = rsvd_region[n].start + xenheap_size;
 	n++;
 
-#ifdef CONFIG_BLK_DEV_INITRD
+	/* This is actually dom0 image */
 	if (ia64_boot_param->initrd_start) {
 		rsvd_region[n].start = (unsigned long)__va(ia64_boot_param->initrd_start);
 		rsvd_region[n].end   = rsvd_region[n].start + ia64_boot_param->initrd_size;
 		n++;
 	}
-#endif
 
 	/* end of memory marker */
 	rsvd_region[n].start = ~0UL;
@@ -204,6 +221,16 @@ reserve_memory (void)
 	num_rsvd_regions = n;
 
 	sort_regions(rsvd_region, num_rsvd_regions);
+
+	{
+		int i;
+		printk("Reserved regions: \n");
+		for (i = 0; i < num_rsvd_regions; i++)
+			printk("  [%d] -> [0x%lx, 0x%lx]\n",
+				i,
+				rsvd_region[i].start,
+				rsvd_region[i].end);
+	}
 }
 
 /**
@@ -298,18 +325,17 @@ mark_bsp_online (void)
 #endif
 }
 
+#ifdef XEN
 void __init
-setup_arch (char **cmdline_p)
+early_setup_arch (char **cmdline_p)
 {
 	unw_init();
 
-	ia64_patch_vtop((u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist);
-
 	*cmdline_p = __va(ia64_boot_param->command_line);
 	strlcpy(saved_command_line, *cmdline_p, COMMAND_LINE_SIZE);
+	cmdline_parse(*cmdline_p);
 
 	efi_init();
-	io_port_init();
 
 #ifdef CONFIG_IA64_GENERIC
 	{
@@ -339,6 +365,10 @@ setup_arch (char **cmdline_p)
 	if (early_console_setup(*cmdline_p) == 0)
 		mark_bsp_online();
 
+#ifdef XEN
+#undef CONFIG_ACPI_BOOT
+#endif
+
 #ifdef CONFIG_ACPI_BOOT
 	/* Initialize the ACPI boot-time table parser */
 	acpi_table_init();
@@ -350,9 +380,13 @@ setup_arch (char **cmdline_p)
 	smp_build_cpu_map();	/* happens, e.g., with the Ski simulator */
 # endif
 #endif /* CONFIG_APCI_BOOT */
+	io_port_init();
+}
+#endif
 
-	find_memory();
-
+void __init
+setup_arch (void)
+{
 	/* process SAL system table: */
 	ia64_sal_init(efi.sal_systab);
 
@@ -388,7 +422,6 @@ setup_arch (char **cmdline_p)
 	if (!strstr(saved_command_line, "nomca"))
 		ia64_mca_init();
 
-	platform_setup(cmdline_p);
 	paging_init();
 }
 
@@ -448,6 +481,9 @@ show_cpuinfo (struct seq_file *m, void *
 		sprintf(cp, " 0x%lx", mask);
 	}
 
+#ifdef XEN
+#define seq_printf(a,b...) printf(b)
+#endif
 	seq_printf(m,
 		   "processor  : %d\n"
 		   "vendor     : %s\n"
@@ -659,11 +695,17 @@ cpu_init (void)
 					| IA64_DCR_DA | IA64_DCR_DD | IA64_DCR_LC));
 	atomic_inc(&init_mm.mm_count);
 	current->active_mm = &init_mm;
+#ifdef XEN
+	if (current->domain->arch.mm)
+#else
 	if (current->mm)
+#endif
 		BUG();
 
 	ia64_mmu_init(ia64_imva(cpu_data));
+#ifndef XEN
 	ia64_mca_cpu_init(ia64_imva(cpu_data));
+#endif
 
 #ifdef CONFIG_IA32_SUPPORT
 	ia32_cpu_init();
@@ -711,6 +753,8 @@ cpu_init (void)
 void
 check_bugs (void)
 {
+#ifndef XEN
 	ia64_patch_mckinley_e9((unsigned long) __start___mckinley_e9_bundles,
 			       (unsigned long) __end___mckinley_e9_bundles);
+#endif
 }
