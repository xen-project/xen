 hardirq.h |    1 +
 1 files changed, 1 insertion(+)

Index: linux-2.6.11-xendiffs/include/asm-ia64/hardirq.h
===================================================================
--- linux-2.6.11-xendiffs.orig/include/asm-ia64/hardirq.h	2005-03-24 15:59:37.210502749 -0600
+++ linux-2.6.11-xendiffs/include/asm-ia64/hardirq.h	2005-03-24 16:00:19.439540961 -0600
@@ -20,6 +20,7 @@
 #define __ARCH_IRQ_STAT	1
 
 #define local_softirq_pending()		(local_cpu_data->softirq_pending)
+#define softirq_pending(cpu)			(cpu_data(cpu)->softirq_pending)
 
 #define HARDIRQ_BITS	14
 
