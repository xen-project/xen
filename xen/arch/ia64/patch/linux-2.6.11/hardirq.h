--- ../../linux-2.6.11/include/linux/hardirq.h	2005-03-02 00:38:00.000000000 -0700
+++ include/asm-ia64/linux/hardirq.h	2005-04-28 16:34:39.000000000 -0600
@@ -60,7 +60,11 @@
  */
 #define in_irq()		(hardirq_count())
 #define in_softirq()		(softirq_count())
+#ifndef XEN
 #define in_interrupt()		(irq_count())
+#else
+#define in_interrupt()		0		// FIXME LATER
+#endif
 
 #if defined(CONFIG_PREEMPT) && !defined(CONFIG_PREEMPT_BKL)
 # define in_atomic()	((preempt_count() & ~PREEMPT_ACTIVE) != kernel_locked())
