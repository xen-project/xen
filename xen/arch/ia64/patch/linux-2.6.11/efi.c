--- ../../linux-2.6.11/arch/ia64/kernel/efi.c	2005-03-02 00:37:47.000000000 -0700
+++ arch/ia64/efi.c	2005-04-29 14:09:24.000000000 -0600
@@ -320,6 +320,10 @@
 		if (!(md->attribute & EFI_MEMORY_WB))
 			continue;
 
+#ifdef XEN
+// this is a temporary hack to avoid CONFIG_VIRTUAL_MEM_MAP
+		if (md->phys_addr >= 0x100000000) continue;
+#endif
 		/*
 		 * granule_addr is the base of md's first granule.
 		 * [granule_addr - first_non_wb_addr) is guaranteed to
@@ -719,6 +723,30 @@
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
