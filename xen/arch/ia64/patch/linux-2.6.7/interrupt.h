--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/interrupt.h	2004-06-15 23:19:29.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/linux/interrupt.h	2004-08-25 19:28:13.000000000 -0600
@@ -32,6 +32,7 @@
 #define IRQ_HANDLED	(1)
 #define IRQ_RETVAL(x)	((x) != 0)
 
+#ifndef XEN
 struct irqaction {
 	irqreturn_t (*handler)(int, void *, struct pt_regs *);
 	unsigned long flags;
@@ -46,6 +47,7 @@
 		       irqreturn_t (*handler)(int, void *, struct pt_regs *),
 		       unsigned long, const char *, void *);
 extern void free_irq(unsigned int, void *);
+#endif
 
 /*
  * Temporary defines for UP kernels, until all code gets fixed.
