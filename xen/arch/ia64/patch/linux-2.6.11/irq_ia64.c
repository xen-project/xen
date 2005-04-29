--- ../../linux-2.6.11/arch/ia64/kernel/irq_ia64.c	2005-03-02 00:38:07.000000000 -0700
+++ arch/ia64/irq_ia64.c	2005-04-29 16:05:30.000000000 -0600
@@ -106,6 +106,9 @@
 	unsigned long saved_tpr;
 
 #if IRQ_DEBUG
+#ifdef XEN
+	xen_debug_irq(vector, regs);
+#endif
 	{
 		unsigned long bsp, sp;
 
@@ -148,6 +151,9 @@
 			ia64_setreg(_IA64_REG_CR_TPR, vector);
 			ia64_srlz_d();
 
+#ifdef XEN
+			if (!xen_do_IRQ(vector))
+#endif
 			__do_IRQ(local_vector_to_irq(vector), regs);
 
 			/*
