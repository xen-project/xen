--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/hp/sim/hpsim_irq.c	2004-06-15 23:20:26.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/hpsim_irq.c	2004-11-01 17:54:15.000000000 -0700
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
@@ -19,6 +29,10 @@
 static void
 hpsim_irq_noop (unsigned int irq)
 {
+#if 1
+printf("hpsim_irq_noop: irq=%d\n",irq);
+while(irq);
+#endif
 }
 
 static struct hw_interrupt_type irq_type_hp_sim = {
@@ -44,3 +58,4 @@
 			idesc->handler = &irq_type_hp_sim;
 	}
 }
+#endif
