--- ../../linux-2.6.7/include/asm-ia64/pgalloc.h	2004-06-15 23:18:54.000000000 -0600
+++ include/asm-ia64/pgalloc.h	2005-03-23 14:54:11.000000000 -0700
@@ -34,6 +34,10 @@
 #define pmd_quicklist		(local_cpu_data->pmd_quick)
 #define pgtable_cache_size	(local_cpu_data->pgtable_cache_sz)
 
+/* FIXME: Later 3 level page table should be over, to create 
+ * new interface upon xen memory allocator. To simplify first
+ * effort moving to xen allocator, use xenheap pages temporarily. 
+ */
 static inline pgd_t*
 pgd_alloc_one_fast (struct mm_struct *mm)
 {
@@ -55,7 +59,7 @@
 	pgd_t *pgd = pgd_alloc_one_fast(mm);
 
 	if (unlikely(pgd == NULL)) {
-		pgd = (pgd_t *)__get_free_page(GFP_KERNEL);
+		pgd = (pgd_t *)alloc_xenheap_page();
 		if (likely(pgd != NULL))
 			clear_page(pgd);
 	}
@@ -93,7 +97,7 @@
 static inline pmd_t*
 pmd_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
-	pmd_t *pmd = (pmd_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT);
+	pmd_t *pmd = (pmd_t *)alloc_xenheap_page();
 
 	if (likely(pmd != NULL))
 		clear_page(pmd);
@@ -125,7 +129,7 @@
 static inline struct page *
 pte_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
-	struct page *pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT, 0);
+	struct page *pte = alloc_xenheap_page();
 
 	if (likely(pte != NULL))
 		clear_page(page_address(pte));
@@ -135,7 +139,7 @@
 static inline pte_t *
 pte_alloc_one_kernel (struct mm_struct *mm, unsigned long addr)
 {
-	pte_t *pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT);
+	pte_t *pte = (pte_t *)alloc_xenheap_page();
 
 	if (likely(pte != NULL))
 		clear_page(pte);
@@ -145,13 +149,13 @@
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
