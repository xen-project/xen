 hardirq.h |    6 ++++++
 1 files changed, 6 insertions(+)

Index: linux-2.6.11-xendiffs/include/linux/hardirq.h
===================================================================
--- linux-2.6.11-xendiffs.orig/include/linux/hardirq.h	2005-03-02 01:38:00.000000000 -0600
+++ linux-2.6.11-xendiffs/include/linux/hardirq.h	2005-03-25 08:49:57.301998663 -0600
@@ -2,7 +2,9 @@
 #define LINUX_HARDIRQ_H
 
 #include <linux/config.h>
+#ifndef XEN
 #include <linux/smp_lock.h>
+#endif
 #include <asm/hardirq.h>
 #include <asm/system.h>
 
@@ -60,7 +62,11 @@
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
