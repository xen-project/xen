--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/hw_irq.h	2004-06-15 23:19:22.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/hw_irq.h	2004-08-27 09:07:38.000000000 -0600
@@ -9,7 +9,9 @@
 #include <linux/interrupt.h>
 #include <linux/sched.h>
 #include <linux/types.h>
+#ifndef XEN
 #include <linux/profile.h>
+#endif
 
 #include <asm/machvec.h>
 #include <asm/ptrace.h>
@@ -96,7 +98,11 @@
  * Default implementations for the irq-descriptor API:
  */
 
+#ifdef XEN
+#define _irq_desc irq_desc
+#else
 extern irq_desc_t _irq_desc[NR_IRQS];
+#endif
 
 #ifndef CONFIG_IA64_GENERIC
 static inline irq_desc_t *
