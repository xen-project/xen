--- ../../linux-2.6.11/include/asm-ia64/pgalloc.h	2005-03-02 00:37:31.000000000 -0700
+++ include/asm-ia64/pgalloc.h	2005-04-29 17:09:20.000000000 -0600
@@ -61,7 +61,11 @@
 	pgd_t *pgd = pgd_alloc_one_fast(mm);
 
 	if (unlikely(pgd == NULL)) {
+#ifdef XEN
+		pgd = (pgd_t *)alloc_xenheap_page();
+#else
 		pgd = (pgd_t *)__get_free_page(GFP_KERNEL|__GFP_ZERO);
+#endif
 	}
 	return pgd;
 }
@@ -104,7 +108,11 @@
 static inline pmd_t*
 pmd_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
+#ifdef XEN
+	pmd_t *pmd = (pmd_t *)alloc_xenheap_page();
+#else
 	pmd_t *pmd = (pmd_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
+#endif
 
 	return pmd;
 }
@@ -136,7 +144,11 @@
 static inline struct page *
 pte_alloc_one (struct mm_struct *mm, unsigned long addr)
 {
+#ifdef XEN
+	struct page *pte = alloc_xenheap_page();
+#else
 	struct page *pte = alloc_pages(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO, 0);
+#endif
 
 	return pte;
 }
@@ -144,7 +156,11 @@
 static inline pte_t *
 pte_alloc_one_kernel (struct mm_struct *mm, unsigned long addr)
 {
+#ifdef XEN
+	pte_t *pte = (pte_t *)alloc_xenheap_page();
+#else
 	pte_t *pte = (pte_t *)__get_free_page(GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO);
+#endif
 
 	return pte;
 }
@@ -152,13 +168,21 @@
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
