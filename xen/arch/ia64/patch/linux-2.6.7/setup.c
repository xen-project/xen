--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/setup.c	2004-06-15 23:18:58.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/setup.c	2004-11-11 17:08:30.000000000 -0700
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
@@ -285,7 +298,9 @@
 {
 	unw_init();
 
+#ifndef XEN
 	ia64_patch_vtop((u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist);
+#endif
 
 	*cmdline_p = __va(ia64_boot_param->command_line);
 	strlcpy(saved_command_line, *cmdline_p, sizeof(saved_command_line));
@@ -297,6 +312,10 @@
 	machvec_init(acpi_get_sysname());
 #endif
 
+#ifdef XEN
+#undef CONFIG_ACPI_BOOT
+#endif
+
 #ifdef CONFIG_ACPI_BOOT
 	/* Initialize the ACPI boot-time table parser */
 	acpi_table_init();
@@ -413,6 +432,9 @@
 		sprintf(cp, " 0x%lx", mask);
 	}
 
+#ifdef XEN
+#define seq_printf(a,b...) printf(b)
+#endif
 	seq_printf(m,
 		   "processor  : %d\n"
 		   "vendor     : %s\n"
@@ -667,6 +689,8 @@
 void
 check_bugs (void)
 {
+#ifndef XEN
 	ia64_patch_mckinley_e9((unsigned long) __start___mckinley_e9_bundles,
 			       (unsigned long) __end___mckinley_e9_bundles);
+#endif
 }
