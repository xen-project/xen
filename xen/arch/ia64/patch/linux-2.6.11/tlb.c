 tlb.c |   10 ++++++++++
 1 files changed, 10 insertions(+)

Index: linux-2.6.11/arch/ia64/mm/tlb.c
===================================================================
--- linux-2.6.11.orig/arch/ia64/mm/tlb.c	2005-03-02 01:38:38.000000000 -0600
+++ linux-2.6.11/arch/ia64/mm/tlb.c	2005-03-19 14:58:43.978400822 -0600
@@ -21,7 +21,9 @@
 #include <asm/mmu_context.h>
 #include <asm/pgalloc.h>
 #include <asm/pal.h>
+#ifndef XEN
 #include <asm/tlbflush.h>
+#endif
 
 static struct {
 	unsigned long mask;	/* mask of supported purge page-sizes */
@@ -43,6 +45,9 @@ DEFINE_PER_CPU(u8, ia64_need_tlb_flush);
 void
 wrap_mmu_context (struct mm_struct *mm)
 {
+#ifdef XEN
+printf("wrap_mmu_context: called, not implemented\n");
+#else
 	unsigned long tsk_context, max_ctx = ia64_ctx.max_ctx;
 	struct task_struct *tsk;
 	int i;
@@ -83,6 +88,7 @@ wrap_mmu_context (struct mm_struct *mm)
 		put_cpu();
 	}
 	local_flush_tlb_all();
+#endif
 }
 
 void
@@ -132,6 +138,9 @@ EXPORT_SYMBOL(local_flush_tlb_all);
 void
 flush_tlb_range (struct vm_area_struct *vma, unsigned long start, unsigned long end)
 {
+#ifdef XEN
+printf("flush_tlb_range: called, not implemented\n");
+#else
 	struct mm_struct *mm = vma->vm_mm;
 	unsigned long size = end - start;
 	unsigned long nbits;
@@ -163,6 +172,7 @@ flush_tlb_range (struct vm_area_struct *
 # endif
 
 	ia64_srlz_i();			/* srlz.i implies srlz.d */
+#endif
 }
 EXPORT_SYMBOL(flush_tlb_range);
 
