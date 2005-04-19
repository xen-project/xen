 interrupt.h |    2 ++
 1 files changed, 2 insertions(+)

Index: linux-2.6.11/include/linux/interrupt.h
===================================================================
--- linux-2.6.11.orig/include/linux/interrupt.h	2005-03-02 01:38:09.000000000 -0600
+++ linux-2.6.11/include/linux/interrupt.h	2005-03-19 13:41:00.739901125 -0600
@@ -33,6 +33,7 @@ typedef int irqreturn_t;
 #define IRQ_HANDLED	(1)
 #define IRQ_RETVAL(x)	((x) != 0)
 
+#ifndef XEN
 struct irqaction {
 	irqreturn_t (*handler)(int, void *, struct pt_regs *);
 	unsigned long flags;
@@ -49,6 +50,7 @@ extern int request_irq(unsigned int,
 		       irqreturn_t (*handler)(int, void *, struct pt_regs *),
 		       unsigned long, const char *, void *);
 extern void free_irq(unsigned int, void *);
+#endif
 
 
 #ifdef CONFIG_GENERIC_HARDIRQS
