--- ../../linux-2.6.7/arch/ia64/kernel/setup.c	2004-06-15 23:18:58.000000000 -0600
+++ arch/ia64/setup.c	2005-03-23 14:54:06.000000000 -0700
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
@@ -50,6 +57,11 @@
 #include <asm/smp.h>
 #include <asm/system.h>
 #include <asm/unistd.h>
+#ifdef XEN
+#include <linux/mm.h>
+#include <asm/mmu_context.h>
+extern unsigned long loops_per_jiffy;	// from linux/init/main.c
+#endif
 
 #if defined(CONFIG_SMP) && (IA64_CPU_SIZE > PAGE_SIZE)
 # error "struct cpuinfo_ia64 too big!"
@@ -65,7 +77,9 @@
 DEFINE_PER_CPU(unsigned long, ia64_phys_stacked_size_p8);
 unsigned long ia64_cycles_per_usec;
 struct ia64_boot_param *ia64_boot_param;
+#ifndef XEN
 struct screen_info screen_info;
+#endif
 
 unsigned long ia64_max_cacheline_size;
 unsigned long ia64_iobase;	/* virtual address for I/O accesses */
@@ -98,7 +112,6 @@
 struct rsvd_region rsvd_region[IA64_MAX_RSVD_REGIONS + 1];
 int num_rsvd_regions;
 
-
 /*
  * Filter incoming memory segments based on the primitive map created from the boot
  * parameters. Segments contained in the map are removed from the memory ranges. A
@@ -128,9 +141,12 @@
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
@@ -187,17 +203,17 @@
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
@@ -207,6 +223,16 @@
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
@@ -280,23 +306,26 @@
 }
 #endif
 
+#ifdef XEN
 void __init
-setup_arch (char **cmdline_p)
+early_setup_arch(char **cmdline_p)
 {
 	unw_init();
-
-	ia64_patch_vtop((u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist);
-
+	
 	*cmdline_p = __va(ia64_boot_param->command_line);
 	strlcpy(saved_command_line, *cmdline_p, sizeof(saved_command_line));
-
+	cmdline_parse(*cmdline_p);
+	
 	efi_init();
-	io_port_init();
-
+	
 #ifdef CONFIG_IA64_GENERIC
 	machvec_init(acpi_get_sysname());
 #endif
 
+#ifdef XEN
+#undef CONFIG_ACPI_BOOT
+#endif
+
 #ifdef CONFIG_ACPI_BOOT
 	/* Initialize the ACPI boot-time table parser */
 	acpi_table_init();
@@ -308,9 +337,13 @@
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
 
@@ -353,7 +386,6 @@
 	/* enable IA-64 Machine Check Abort Handling */
 	ia64_mca_init();
 
-	platform_setup(cmdline_p);
 	paging_init();
 }
 
@@ -413,6 +445,9 @@
 		sprintf(cp, " 0x%lx", mask);
 	}
 
+#ifdef XEN
+#define seq_printf(a,b...) printf(b)
+#endif
 	seq_printf(m,
 		   "processor  : %d\n"
 		   "vendor     : %s\n"
@@ -667,6 +702,8 @@
 void
 check_bugs (void)
 {
+#ifndef XEN
 	ia64_patch_mckinley_e9((unsigned long) __start___mckinley_e9_bundles,
 			       (unsigned long) __end___mckinley_e9_bundles);
+#endif
 }
