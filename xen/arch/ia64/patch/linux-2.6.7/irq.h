--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/irq.h	2005-01-23 13:23:36.000000000 -0700
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/irq.h	2004-08-25 19:28:13.000000000 -0600
@@ -30,6 +30,15 @@
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
