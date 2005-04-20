 irq.h |    9 +++++++++
 1 files changed, 9 insertions(+)

Index: linux-2.6.11/include/asm-ia64/irq.h
===================================================================
--- linux-2.6.11.orig/include/asm-ia64/irq.h	2005-03-02 01:38:33.000000000 -0600
+++ linux-2.6.11/include/asm-ia64/irq.h	2005-03-19 13:42:27.957677364 -0600
@@ -30,6 +30,15 @@ extern void disable_irq_nosync (unsigned
 extern void enable_irq (unsigned int);
 extern void set_irq_affinity_info (unsigned int irq, int dest, int redir);
 
+#ifdef XEN
+// dup'ed from signal.h to avoid changes to includes
+#define	SA_NOPROFILE	0x02000000
+#define	SA_SHIRQ	0x04000000
+#define	SA_RESTART	0x10000000
+#define	SA_INTERRUPT	0x20000000
+#define	SA_SAMPLE_RANDOM	SA_RESTART
+#endif
+
 #ifdef CONFIG_SMP
 extern void move_irq(int irq);
 #else
