--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/include/linux/interrupt.h	2005-03-01 23:38:09.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/include/asm-ia64/linux/interrupt.h	2005-05-18 12:40:50.000000000 -0700
@@ -33,6 +33,7 @@
 #define IRQ_HANDLED	(1)
 #define IRQ_RETVAL(x)	((x) != 0)
 
+#ifndef XEN
 struct irqaction {
 	irqreturn_t (*handler)(int, void *, struct pt_regs *);
 	unsigned long flags;
@@ -49,6 +50,7 @@
 		       irqreturn_t (*handler)(int, void *, struct pt_regs *),
 		       unsigned long, const char *, void *);
 extern void free_irq(unsigned int, void *);
+#endif
 
 
 #ifdef CONFIG_GENERIC_HARDIRQS
@@ -121,7 +123,7 @@
 };
 
 asmlinkage void do_softirq(void);
-extern void open_softirq(int nr, void (*action)(struct softirq_action*), void *data);
+//extern void open_softirq(int nr, void (*action)(struct softirq_action*), void *data);
 extern void softirq_init(void);
 #define __raise_softirq_irqoff(nr) do { local_softirq_pending() |= 1UL << (nr); } while (0)
 extern void FASTCALL(raise_softirq_irqoff(unsigned int nr));
