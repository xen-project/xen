--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/efi.c	2004-06-15 23:18:55.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/efi.c	2004-12-17 13:47:03.000000000 -0700
@@ -25,6 +25,9 @@
 #include <linux/types.h>
 #include <linux/time.h>
 #include <linux/efi.h>
+#ifdef XEN
+#include <xen/sched.h>
+#endif
 
 #include <asm/io.h>
 #include <asm/kregs.h>
@@ -49,7 +52,10 @@
 {												\
 	struct ia64_fpreg fr[6];								\
 	efi_status_t ret;									\
+	efi_time_cap_t *atc = NULL;								\
 												\
+	if (tc)											\
+		atc = adjust_arg(tc);								\
 	ia64_save_scratch_fpregs(fr);								\
 	ret = efi_call_##prefix((efi_get_time_t *) __va(runtime->get_time), adjust_arg(tm),	\
 				adjust_arg(tc));						\
@@ -201,6 +207,7 @@
 	if ((*efi.get_time)(&tm, 0) != EFI_SUCCESS)
 		return;
 
+	dummy();
 	ts->tv_sec = mktime(tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second);
 	ts->tv_nsec = tm.nanosecond;
 }
@@ -303,6 +310,10 @@
 		if (!(md->attribute & EFI_MEMORY_WB))
 			continue;
 
+#ifdef XEN
+// this is a temporary hack to avoid CONFIG_VIRTUAL_MEM_MAP
+		if (md->phys_addr >= 0x100000000) continue;
+#endif
 		/*
 		 * granule_addr is the base of md's first granule.
 		 * [granule_addr - first_non_wb_addr) is guaranteed to
@@ -456,9 +467,11 @@
 
 		cpu = smp_processor_id();
 
+#ifndef XEN
 		/* insert this TR into our list for MCA recovery purposes */
 		ia64_mca_tlb_list[cpu].pal_base = vaddr & mask;
 		ia64_mca_tlb_list[cpu].pal_paddr = pte_val(mk_pte_phys(md->phys_addr, PAGE_KERNEL));
+#endif
 	}
 }
 
@@ -680,6 +693,30 @@
 	return 0;
 }
 
+#ifdef XEN
+// variation of efi_get_iobase which returns entire memory descriptor
+efi_memory_desc_t *
+efi_get_io_md (void)
+{
+	void *efi_map_start, *efi_map_end, *p;
+	efi_memory_desc_t *md;
+	u64 efi_desc_size;
+
+	efi_map_start = __va(ia64_boot_param->efi_memmap);
+	efi_map_end   = efi_map_start + ia64_boot_param->efi_memmap_size;
+	efi_desc_size = ia64_boot_param->efi_memdesc_size;
+
+	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
+		md = p;
+		if (md->type == EFI_MEMORY_MAPPED_IO_PORT_SPACE) {
+			if (md->attribute & EFI_MEMORY_UC)
+				return md;
+		}
+	}
+	return 0;
+}
+#endif
+
 u32
 efi_mem_type (unsigned long phys_addr)
 {
