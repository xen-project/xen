--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/page.h	2004-06-15 23:18:58.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/page.h	2004-12-17 13:47:03.000000000 -0700
@@ -84,7 +84,11 @@
 #endif
 
 #ifndef CONFIG_DISCONTIGMEM
+#ifdef XEN
+#define pfn_valid(pfn)		(0)
+#else
 #define pfn_valid(pfn)		(((pfn) < max_mapnr) && ia64_pfn_valid(pfn))
+#endif
 #define page_to_pfn(page)	((unsigned long) (page - mem_map))
 #define pfn_to_page(pfn)	(mem_map + (pfn))
 #endif /* CONFIG_DISCONTIGMEM */
@@ -107,8 +111,25 @@
  * expressed in this way to ensure they result in a single "dep"
  * instruction.
  */
+#ifdef XEN
+typedef union xen_va {
+	struct {
+		unsigned long off : 50;
+		unsigned long reg : 14;
+	} f;
+	unsigned long l;
+	void *p;
+} xen_va;
+
+// xen/drivers/console.c uses __va in a declaration (should be fixed!)
+#define __pa(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = 0; _v.l;})
+#define __va(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})
+//# define __pa(x)	((unsigned long)(((unsigned long)x) - PAGE_OFFSET))
+//# define __va(x)	((void *)((char *)(x) + PAGE_OFFSET))
+#else
 #define __pa(x)		({ia64_va _v; _v.l = (long) (x); _v.f.reg = 0; _v.l;})
 #define __va(x)		({ia64_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})
+#endif
 
 #define REGION_NUMBER(x)	({ia64_va _v; _v.l = (long) (x); _v.f.reg;})
 #define REGION_OFFSET(x)	({ia64_va _v; _v.l = (long) (x); _v.f.off;})
@@ -180,11 +201,19 @@
 # define __pgprot(x)	(x)
 #endif /* !STRICT_MM_TYPECHECKS */
 
+#ifdef XEN
+#define PAGE_OFFSET			0xfffc000000000000
+#else
 #define PAGE_OFFSET			0xe000000000000000
+#endif
 
 #define VM_DATA_DEFAULT_FLAGS		(VM_READ | VM_WRITE |					\
 					 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC |		\
 					 (((current->thread.flags & IA64_THREAD_XSTACK) != 0)	\
 					  ? VM_EXEC : 0))
 
+#ifdef XEN
+#define __flush_tlb()	do {} while(0);
+#endif
+
 #endif /* _ASM_IA64_PAGE_H */
