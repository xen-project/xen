 irq_ia64.c |   67 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 1 files changed, 67 insertions(+)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/irq_ia64.c
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/irq_ia64.c	2005-04-08 13:30:16.777174938 -0500
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/irq_ia64.c	2005-04-08 14:15:47.398616472 -0500
@@ -17,18 +17,26 @@
 #include <linux/config.h>
 #include <linux/module.h>
 
+#ifndef XEN
 #include <linux/jiffies.h>
+#endif
 #include <linux/errno.h>
 #include <linux/init.h>
 #include <linux/interrupt.h>
 #include <linux/ioport.h>
+#ifndef XEN
 #include <linux/kernel_stat.h>
+#endif
 #include <linux/slab.h>
+#ifndef XEN
 #include <linux/ptrace.h>
 #include <linux/random.h>	/* for rand_initialize_irq() */
 #include <linux/signal.h>
+#endif
 #include <linux/smp.h>
+#ifndef XEN
 #include <linux/smp_lock.h>
+#endif
 #include <linux/threads.h>
 #include <linux/bitops.h>
 
@@ -104,6 +112,24 @@ void
 ia64_handle_irq (ia64_vector vector, struct pt_regs *regs)
 {
 	unsigned long saved_tpr;
+#if 0
+//FIXME: For debug only, can be removed
+	static char firstirq = 1;
+	static char firsttime[256];
+	static char firstpend[256];
+	if (firstirq) {
+		int i;
+		for (i=0;i<256;i++) firsttime[i] = 1;
+		for (i=0;i<256;i++) firstpend[i] = 1;
+		firstirq = 0;
+	}
+	if (firsttime[vector]) {
+		printf("**** (entry) First received int on vector=%d,itc=%lx\n",
+			(unsigned long) vector, ia64_get_itc());
+		firsttime[vector] = 0;
+	}
+#endif
+
 
 #if IRQ_DEBUG
 	{
@@ -148,6 +174,27 @@ ia64_handle_irq (ia64_vector vector, str
 			ia64_setreg(_IA64_REG_CR_TPR, vector);
 			ia64_srlz_d();
 
+#ifdef XEN
+	if (vector != 0xef) {
+		extern void vcpu_pend_interrupt(void *, int);
+#if 0
+		if (firsttime[vector]) {
+			printf("**** (iterate) First received int on vector=%d,itc=%lx\n",
+			(unsigned long) vector, ia64_get_itc());
+			firsttime[vector] = 0;
+		}
+		if (firstpend[vector]) {
+			printf("**** First pended int on vector=%d,itc=%lx\n",
+				(unsigned long) vector,ia64_get_itc());
+			firstpend[vector] = 0;
+		}
+#endif
+		//FIXME: TEMPORARY HACK!!!!
+		vcpu_pend_interrupt(dom0->exec_domain[0],vector);
+		domain_wake(dom0->exec_domain[0]);
+	}
+	else
+#endif
 			__do_IRQ(local_vector_to_irq(vector), regs);
 
 			/*
@@ -276,3 +323,23 @@ ia64_send_ipi (int cpu, int vector, int 
 
 	writeq(ipi_data, ipi_addr);
 }
+
+/* From linux/kernel/softirq.c */
+#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
+# define invoke_softirq()	__do_softirq()
+#else
+# define invoke_softirq()	do_softirq()
+#endif
+
+/*
+ * Exit an interrupt context. Process softirqs if needed and possible:
+ */
+void irq_exit(void)
+{
+	account_system_vtime(current);
+	sub_preempt_count(IRQ_EXIT_OFFSET);
+	if (!in_interrupt() && local_softirq_pending())
+		invoke_softirq();
+	preempt_enable_no_resched();
+}
+/* end from linux/kernel/softirq.c */
