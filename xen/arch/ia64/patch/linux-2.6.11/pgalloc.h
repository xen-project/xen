 pgalloc.h |   17 +++++++++++------
 1 files changed, 11 insertions(+), 6 deletions(-)

Index: linux-2.6.11-xendiffs/include/asm-ia64/pgalloc.h
===================================================================
--- linux-2.6.11-xendiffs.orig/include/asm-ia64/pgalloc.h	2005-04-08 11:57:30.909774800 -0500
+++ linux-2.6.11-xendiffs/include/asm-ia64/pgalloc.h	2005-04-08 11:58:08.102711219 -0500
@@ -18,6 +18,7 @@
 #include <linux/compiler.h>
 #include <linux/mm.h>
 #include <linux/page-flags.h>
+#include <linux/preempt.h>
 #include <linux/threads.h>
 
 #include <asm/mmu_context.h>
@@ -34,6 +35,10 @@
 #define pmd_quicklist		(local_cpu_data->pmd_quick)
 #define pgtable_cache_size	(local_cpu_data->pgtable_cache_sz)
 
+/* FIXME: Later 3 level page table should be over, to create 
+ * new interface upon xen memory allocator. To simplify first
+ * effort moving to xen allocator, use xenheap pages temporarily. 
+ */
 static inline pgd_t*
 pgd_alloc_one_fast (struct mm_struct *mm)
 {
@@ -61,7 +66,7 @@ pgd_alloc (struct mm_struct *mm)
 	pgd_t *pgd = pgd_alloc_one_fast(mm);
 
 	if (unlikely(pgd == NULL)) {
-		pgd = (pgd_t *)__get_free_page(GFP_KERNEL|__GFP_ZERO);
+		pgd = (pgd_t *)alloc_xenheap_page();
 	}
 	return pgd;
 }
@@ -104,7 +109,7 @@ pmd_alloc_one_fast (struct mm_struct *mm
 static inline pmd_t*
 pmd_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
-	pmd_t *pmd = (pmd_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
+	pmd_t *pmd = (pmd_t *)alloc_xenheap_page();
 
 	return pmd;
 }
@@ -136,7 +141,7 @@ pmd_populate_kernel (struct mm_struct *m
 static inline struct page *
 pte_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
-	struct page *pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
+	struct page *pte = alloc_xenheap_page();
 
 	return pte;
 }
@@ -144,7 +149,7 @@ pte_alloc_one (struct mm_struct *mm, uns
 static inline pte_t *
 pte_alloc_one_kernel (struct mm_struct *mm, unsigned long addr)
 {
-	pte_t *pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
+	pte_t *pte = (pte_t *)alloc_xenheap_page();
 
 	return pte;
 }
@@ -152,13 +157,13 @@ pte_alloc_one_kernel (struct mm_struct *
 static inline void
 pte_free (struct page *pte)
 {
-	__free_page(pte);
+	free_xenheap_page(pte);
 }
 
 static inline void
 pte_free_kernel (pte_t *pte)
 {
-	free_page((unsigned long) pte);
+	free_xenheap_page((unsigned long) pte);
 }
 
 #define __pte_free_tlb(tlb, pte)	tlb_remove_page((tlb), (pte))
