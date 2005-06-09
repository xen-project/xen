--- ../../linux-2.6.11/include/asm-ia64/pgalloc.h	2005-03-02 00:37:31.000000000 -0700
+++ include/asm-ia64/pgalloc.h	2005-06-09 13:40:48.000000000 -0600
@@ -61,7 +61,12 @@
 	pgd_t *pgd = pgd_alloc_one_fast(mm);
 
 	if (unlikely(pgd == NULL)) {
+#ifdef XEN
+		pgd = (pgd_t *)alloc_xenheap_page();
+		memset(pgd,0,PAGE_SIZE);
+#else
 		pgd = (pgd_t *)__get_free_page(GFP_KERNEL|__GFP_ZERO);
+#endif
 	}
 	return pgd;
 }
@@ -104,7 +109,12 @@
 static inline pmd_t*
 pmd_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
+#ifdef XEN
+	pmd_t *pmd = (pmd_t *)alloc_xenheap_page();
+	memset(pmd,0,PAGE_SIZE);
+#else
 	pmd_t *pmd = (pmd_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
+#endif
 
 	return pmd;
 }
@@ -136,7 +146,12 @@
 static inline struct page *
 pte_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
+#ifdef XEN
+	struct page *pte = alloc_xenheap_page();
+	memset(pte,0,PAGE_SIZE);
+#else
 	struct page *pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
+#endif
 
 	return pte;
 }
@@ -144,7 +159,12 @@
 static inline pte_t *
 pte_alloc_one_kernel (struct mm_struct *mm, unsigned long addr)
 {
+#ifdef XEN
+	pte_t *pte = (pte_t *)alloc_xenheap_page();
+	memset(pte,0,PAGE_SIZE);
+#else
 	pte_t *pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
+#endif
 
 	return pte;
 }
@@ -152,13 +172,21 @@
 static inline void
 pte_free (struct page *pte)
 {
+#ifdef XEN
+	free_xenheap_page(pte);
+#else
 	__free_page(pte);
+#endif
 }
 
 static inline void
 pte_free_kernel (pte_t *pte)
 {
+#ifdef XEN
+	free_xenheap_page((unsigned long) pte);
+#else
 	free_page((unsigned long) pte);
+#endif
 }
 
 #define __pte_free_tlb(tlb, pte)	tlb_remove_page((tlb), (pte))
