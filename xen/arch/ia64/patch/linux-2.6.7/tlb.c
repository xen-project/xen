--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/mm/tlb.c	2004-06-15 23:19:43.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/tlb.c	2004-08-25 19:28:12.000000000 -0600
@@ -21,7 +21,9 @@
 #include <asm/mmu_context.h>
 #include <asm/pgalloc.h>
 #include <asm/pal.h>
+#ifndef XEN
 #include <asm/tlbflush.h>
+#endif
 
 static struct {
 	unsigned long mask;	/* mask of supported purge page-sizes */
@@ -43,6 +45,9 @@
 void
 wrap_mmu_context (struct mm_struct *mm)
 {
+#ifdef XEN
+printf("wrap_mmu_context: called, not implemented\n");
+#else
 	unsigned long tsk_context, max_ctx = ia64_ctx.max_ctx;
 	struct task_struct *tsk;
 	int i;
@@ -83,6 +88,7 @@
 		put_cpu();
 	}
 	local_flush_tlb_all();
+#endif
 }
 
 void
@@ -132,6 +138,9 @@
 void
 flush_tlb_range (struct vm_area_struct *vma, unsigned long start, unsigned long end)
 {
+#ifdef XEN
+printf("flush_tlb_range: called, not implemented\n");
+#else
 	struct mm_struct *mm = vma->vm_mm;
 	unsigned long size = end - start;
 	unsigned long nbits;
@@ -163,6 +172,7 @@
 # endif
 
 	ia64_srlz_i();			/* srlz.i implies srlz.d */
+#endif
 }
 EXPORT_SYMBOL(flush_tlb_range);
 
