 hpsim_irq.c |   15 +++++++++++++++
 1 files changed, 15 insertions(+)

Index: linux-2.6.11/arch/ia64/hp/sim/hpsim_irq.c
===================================================================
--- linux-2.6.11.orig/arch/ia64/hp/sim/hpsim_irq.c	2005-03-02 01:38:33.000000000 -0600
+++ linux-2.6.11/arch/ia64/hp/sim/hpsim_irq.c	2005-03-19 13:33:57.312014806 -0600
@@ -9,7 +9,17 @@
 #include <linux/kernel.h>
 #include <linux/sched.h>
 #include <linux/irq.h>
+#ifdef XEN
+#include <asm/hw_irq.h>
+#endif
 
+#if 1
+void __init
+hpsim_irq_init (void)
+{
+	printf("*** hpsim_irq_init called: NOT NEEDED?!?!?\n");
+}
+#else
 static unsigned int
 hpsim_irq_startup (unsigned int irq)
 {
@@ -19,6 +29,10 @@ hpsim_irq_startup (unsigned int irq)
 static void
 hpsim_irq_noop (unsigned int irq)
 {
+#if 1
+printf("hpsim_irq_noop: irq=%d\n",irq);
+while(irq);
+#endif
 }
 
 static void
@@ -49,3 +63,4 @@ hpsim_irq_init (void)
 			idesc->handler = &irq_type_hp_sim;
 	}
 }
+#endif
