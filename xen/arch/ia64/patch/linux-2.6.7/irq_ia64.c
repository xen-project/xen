--- /home/djm/linux-2.6.7/arch/ia64/kernel/irq_ia64.c	2004-06-15 23:19:13.000000000 -0600
+++ arch/ia64/irq_ia64.c	2005-02-17 13:06:07.000000000 -0700
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
 
 #include <asm/bitops.h>
@@ -101,6 +109,24 @@
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
@@ -145,6 +171,27 @@
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
+		domain_wake(dom0);
+	}
+	else
+#endif
 			do_IRQ(local_vector_to_irq(vector), regs);
 
 			/*
