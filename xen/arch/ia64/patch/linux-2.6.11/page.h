--- ../../linux-2.6.11/include/asm-ia64/page.h	2005-03-02 00:37:48.000000000 -0700
+++ include/asm-ia64/page.h	2005-05-02 11:25:33.000000000 -0600
@@ -95,9 +95,15 @@
 #endif
 
 #ifndef CONFIG_DISCONTIGMEM
+#ifdef XEN
+# define pfn_valid(pfn)		(0)
+# define page_to_pfn(_page)	((unsigned long)((_page) - frame_table))
+# define pfn_to_page(_pfn)	(frame_table + (_pfn))
+#else
 # define pfn_valid(pfn)		(((pfn) < max_mapnr) && ia64_pfn_valid(pfn))
 # define page_to_pfn(page)	((unsigned long) (page - mem_map))
 # define pfn_to_page(pfn)	(mem_map + (pfn))
+#endif
 #else
 extern struct page *vmem_map;
 extern unsigned long max_low_pfn;
@@ -109,6 +115,11 @@
 #define page_to_phys(page)	(page_to_pfn(page) << PAGE_SHIFT)
 #define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
 
+#ifdef XEN
+#define page_to_virt(_page)	phys_to_virt(page_to_phys(_page))
+#define phys_to_page(kaddr)	pfn_to_page(((kaddr) >> PAGE_SHIFT))
+#endif
+
 typedef union ia64_va {
 	struct {
 		unsigned long off : 61;		/* intra-region offset */
@@ -124,8 +135,23 @@
  * expressed in this way to ensure they result in a single "dep"
  * instruction.
  */
+#ifdef XEN
+typedef union xen_va {
+	struct {
+		unsigned long off : 60;
+		unsigned long reg : 4;
+	} f;
+	unsigned long l;
+	void *p;
+} xen_va;
+
+// xen/drivers/console.c uses __va in a declaration (should be fixed!)
+#define __pa(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = 0; _v.l;})
+#define __va(x)		({xen_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})
+#else
 #define __pa(x)		({ia64_va _v; _v.l = (long) (x); _v.f.reg = 0; _v.l;})
 #define __va(x)		({ia64_va _v; _v.l = (long) (x); _v.f.reg = -1; _v.p;})
+#endif
 
 #define REGION_NUMBER(x)	({ia64_va _v; _v.l = (long) (x); _v.f.reg;})
 #define REGION_OFFSET(x)	({ia64_va _v; _v.l = (long) (x); _v.f.off;})
@@ -197,7 +223,11 @@
 # define __pgprot(x)	(x)
 #endif /* !STRICT_MM_TYPECHECKS */
 
+#ifdef XEN
+#define PAGE_OFFSET			__IA64_UL_CONST(0xf000000000000000)
+#else
 #define PAGE_OFFSET			__IA64_UL_CONST(0xe000000000000000)
+#endif
 
 #define VM_DATA_DEFAULT_FLAGS		(VM_READ | VM_WRITE |					\
 					 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC |		\
