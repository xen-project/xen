--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/hardirq.h	2004-06-15 23:19:02.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/hardirq.h	2004-12-17 13:47:03.000000000 -0700
@@ -81,10 +81,19 @@
  */
 #define in_irq()		(hardirq_count())
 #define in_softirq()		(softirq_count())
+#ifdef XEN
 #define in_interrupt()		(irq_count())
+#else
+#define in_interrupt()		0		// FIXME LATER
+#endif
 
+#ifdef XEN
+#define hardirq_trylock(cpu)	(!in_interrupt())
+#define hardirq_endlock(cpu)	do { } while (0)
+#else
 #define hardirq_trylock()	(!in_interrupt())
 #define hardirq_endlock()	do { } while (0)
+#endif
 
 #ifdef CONFIG_PREEMPT
 # include <linux/smp_lock.h>
