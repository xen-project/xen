--- ../../linux-2.6.11/arch/ia64/kernel/setup.c	2005-03-02 00:37:49.000000000 -0700
+++ arch/ia64/setup.c	2005-05-02 10:04:03.000000000 -0600
@@ -127,7 +127,16 @@
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
@@ -185,7 +194,12 @@
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
@@ -299,7 +313,11 @@
 }
 
 void __init
+#ifdef XEN
+early_setup_arch (char **cmdline_p)
+#else
 setup_arch (char **cmdline_p)
+#endif
 {
 	unw_init();
 
@@ -308,8 +326,14 @@
 	*cmdline_p = __va(ia64_boot_param->command_line);
 	strlcpy(saved_command_line, *cmdline_p, COMMAND_LINE_SIZE);
 
+#ifdef XEN
+	cmdline_parse(*cmdline_p);
+#undef CONFIG_ACPI_BOOT
+#endif
 	efi_init();
+#ifndef XEN
 	io_port_init();
+#endif
 
 #ifdef CONFIG_IA64_GENERIC
 	{
@@ -351,8 +375,17 @@
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
+#endif
 	/* process SAL system table: */
 	ia64_sal_init(efi.sal_systab);
 
@@ -492,12 +525,14 @@
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
@@ -659,7 +694,11 @@
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
