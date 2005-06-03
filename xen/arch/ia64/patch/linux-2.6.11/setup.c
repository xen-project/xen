--- ../../linux-2.6.11/arch/ia64/kernel/setup.c	2005-03-02 00:37:49.000000000 -0700
+++ arch/ia64/setup.c	2005-06-03 10:14:24.000000000 -0600
@@ -51,6 +51,10 @@
 #include <asm/smp.h>
 #include <asm/system.h>
 #include <asm/unistd.h>
+#ifdef CONFIG_VTI
+#include <asm/vmx.h>
+#endif // CONFIG_VTI
+#include <asm/io.h>
 
 #if defined(CONFIG_SMP) && (IA64_CPU_SIZE > PAGE_SIZE)
 # error "struct cpuinfo_ia64 too big!"
@@ -127,7 +131,16 @@
 		range_end   = min(end, rsvd_region[i].start);
 
 		if (range_start < range_end)
+#ifdef XEN
+		{
+		/* init_boot_pages requires "ps, pe" */
+			printk("Init boot pages: 0x%lx -> 0x%lx.\n",
+				__pa(range_start), __pa(range_end));
+			(*func)(__pa(range_start), __pa(range_end), 0);
+		}
+#else
 			call_pernode_memory(__pa(range_start), range_end - range_start, func);
+#endif
 
 		/* nothing more available in this segment */
 		if (range_end == end) return 0;
@@ -185,7 +198,12 @@
 	n++;
 
 	rsvd_region[n].start = (unsigned long) ia64_imva((void *)KERNEL_START);
+#ifdef XEN
+	/* Reserve xen image/bitmap/xen-heap */
+	rsvd_region[n].end   = rsvd_region[n].start + xenheap_size;
+#else
 	rsvd_region[n].end   = (unsigned long) ia64_imva(_end);
+#endif
 	n++;
 
 #ifdef CONFIG_BLK_DEV_INITRD
@@ -299,17 +317,25 @@
 }
 
 void __init
+#ifdef XEN
+early_setup_arch (char **cmdline_p)
+#else
 setup_arch (char **cmdline_p)
+#endif
 {
 	unw_init();
 
 	ia64_patch_vtop((u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist);
 
 	*cmdline_p = __va(ia64_boot_param->command_line);
+#ifdef XEN
+	efi_init();
+#else
 	strlcpy(saved_command_line, *cmdline_p, COMMAND_LINE_SIZE);
 
 	efi_init();
 	io_port_init();
+#endif
 
 #ifdef CONFIG_IA64_GENERIC
 	{
@@ -336,6 +362,11 @@
 	}
 #endif
 
+#ifdef XEN
+	early_cmdline_parse(cmdline_p);
+	cmdline_parse(*cmdline_p);
+#undef CONFIG_ACPI_BOOT
+#endif
 	if (early_console_setup(*cmdline_p) == 0)
 		mark_bsp_online();
 
@@ -351,8 +382,18 @@
 # endif
 #endif /* CONFIG_APCI_BOOT */
 
+#ifndef XEN
 	find_memory();
+#else
+	io_port_init();
+}
 
+void __init
+late_setup_arch (char **cmdline_p)
+{
+#undef CONFIG_ACPI_BOOT
+	acpi_table_init();
+#endif
 	/* process SAL system table: */
 	ia64_sal_init(efi.sal_systab);
 
@@ -360,6 +401,10 @@
 	cpu_physical_id(0) = hard_smp_processor_id();
 #endif
 
+#ifdef CONFIG_VTI
+	identify_vmx_feature();
+#endif // CONFIG_VTI
+
 	cpu_init();	/* initialize the bootstrap CPU */
 
 #ifdef CONFIG_ACPI_BOOT
@@ -492,12 +537,14 @@
 {
 }
 
+#ifndef XEN
 struct seq_operations cpuinfo_op = {
 	.start =	c_start,
 	.next =		c_next,
 	.stop =		c_stop,
 	.show =		show_cpuinfo
 };
+#endif
 
 void
 identify_cpu (struct cpuinfo_ia64 *c)
@@ -551,6 +598,12 @@
 	}
 	c->unimpl_va_mask = ~((7L<<61) | ((1L << (impl_va_msb + 1)) - 1));
 	c->unimpl_pa_mask = ~((1L<<63) | ((1L << phys_addr_size) - 1));
+
+#ifdef CONFIG_VTI
+	/* If vmx feature is on, do necessary initialization for vmx */
+	if (vmx_enabled)
+		vmx_init_env();
+#endif
 }
 
 void
@@ -659,7 +712,11 @@
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
