--- ../../linux-2.6.11/arch/ia64/mm/tlb.c	2005-03-02 00:38:38.000000000 -0700
+++ arch/ia64/tlb.c	2005-05-02 10:23:09.000000000 -0600
@@ -43,6 +43,9 @@
 void
 wrap_mmu_context (struct mm_struct *mm)
 {
+#ifdef XEN
+printf("wrap_mmu_context: called, not implemented\n");
+#else
 	unsigned long tsk_context, max_ctx = ia64_ctx.max_ctx;
 	struct task_struct *tsk;
 	int i;
@@ -83,6 +86,7 @@
 		put_cpu();
 	}
 	local_flush_tlb_all();
+#endif
 }
 
 void
@@ -132,6 +136,9 @@
 void
 flush_tlb_range (struct vm_area_struct *vma, unsigned long start, unsigned long end)
 {
+#ifdef XEN
+printf("flush_tlb_range: called, not implemented\n");
+#else
 	struct mm_struct *mm = vma->vm_mm;
 	unsigned long size = end - start;
 	unsigned long nbits;
@@ -163,6 +170,7 @@
 # endif
 
 	ia64_srlz_i();			/* srlz.i implies srlz.d */
+#endif
 }
 EXPORT_SYMBOL(flush_tlb_range);
 
