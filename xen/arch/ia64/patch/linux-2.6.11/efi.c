 efi.c |   32 ++++++++++++++++++++++++++++++++
 1 files changed, 32 insertions(+)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/efi.c
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/efi.c	2005-04-07 12:22:08.230781400 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/efi.c	2005-04-07 12:25:11.875195997 -0500
@@ -25,6 +25,9 @@
 #include <linux/types.h>
 #include <linux/time.h>
 #include <linux/efi.h>
+#ifdef XEN
+#include <xen/sched.h>
+#endif
 
 #include <asm/io.h>
 #include <asm/kregs.h>
@@ -218,6 +221,7 @@ efi_gettimeofday (struct timespec *ts)
 	if ((*efi.get_time)(&tm, NULL) != EFI_SUCCESS)
 		return;
 
+	dummy();
 	ts->tv_sec = mktime(tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second);
 	ts->tv_nsec = tm.nanosecond;
 }
@@ -320,6 +324,10 @@ efi_memmap_walk (efi_freemem_callback_t 
 		if (!(md->attribute & EFI_MEMORY_WB))
 			continue;
 
+#ifdef XEN
+// this is a temporary hack to avoid CONFIG_VIRTUAL_MEM_MAP
+		if (md->phys_addr >= 0x100000000) continue;
+#endif
 		/*
 		 * granule_addr is the base of md's first granule.
 		 * [granule_addr - first_non_wb_addr) is guaranteed to
@@ -719,6 +727,30 @@ efi_get_iobase (void)
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
