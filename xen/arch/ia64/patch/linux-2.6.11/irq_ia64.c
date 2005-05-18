--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/arch/ia64/kernel/irq_ia64.c	2005-03-01 23:38:07.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/arch/ia64/irq_ia64.c	2005-05-18 12:40:51.000000000 -0700
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
@@ -167,6 +173,95 @@
 	irq_exit();
 }
 
+#ifdef  CONFIG_VTI
+/*
+ * That's where the IVT branches when we get an external
+ * interrupt. This branches to the correct hardware IRQ handler via
+ * function ptr.
+ */
+void
+vmx_ia64_handle_irq (ia64_vector vector, struct pt_regs *regs)
+{
+	unsigned long saved_tpr;
+	int	wake_dom0 = 0;
+
+
+#if IRQ_DEBUG
+	{
+		unsigned long bsp, sp;
+
+		/*
+		 * Note: if the interrupt happened while executing in
+		 * the context switch routine (ia64_switch_to), we may
+		 * get a spurious stack overflow here.  This is
+		 * because the register and the memory stack are not
+		 * switched atomically.
+		 */
+		bsp = ia64_getreg(_IA64_REG_AR_BSP);
+		sp = ia64_getreg(_IA64_REG_AR_SP);
+
+		if ((sp - bsp) < 1024) {
+			static unsigned char count;
+			static long last_time;
+
+			if (jiffies - last_time > 5*HZ)
+				count = 0;
+			if (++count < 5) {
+				last_time = jiffies;
+				printk("ia64_handle_irq: DANGER: less than "
+				       "1KB of free stack space!!\n"
+				       "(bsp=0x%lx, sp=%lx)\n", bsp, sp);
+			}
+		}
+	}
+#endif /* IRQ_DEBUG */
+
+	/*
+	 * Always set TPR to limit maximum interrupt nesting depth to
+	 * 16 (without this, it would be ~240, which could easily lead
+	 * to kernel stack overflows).
+	 */
+	irq_enter();
+	saved_tpr = ia64_getreg(_IA64_REG_CR_TPR);
+	ia64_srlz_d();
+	while (vector != IA64_SPURIOUS_INT_VECTOR) {
+	    if (!IS_RESCHEDULE(vector)) {
+		ia64_setreg(_IA64_REG_CR_TPR, vector);
+		ia64_srlz_d();
+
+		if (vector != IA64_TIMER_VECTOR) {
+			/* FIXME: Leave IRQ re-route later */
+			vmx_vcpu_pend_interrupt(dom0->exec_domain[0],vector);
+			wake_dom0 = 1;
+		}
+		else {	// FIXME: Handle Timer only now
+			__do_IRQ(local_vector_to_irq(vector), regs);
+		}
+		
+		/*
+		 * Disable interrupts and send EOI:
+		 */
+		local_irq_disable();
+		ia64_setreg(_IA64_REG_CR_TPR, saved_tpr);
+	    }
+	    else {
+                printf("Oops: RESCHEDULE IPI absorbed by HV\n");
+            }
+	    ia64_eoi();
+	    vector = ia64_get_ivr();
+	}
+	/*
+	 * This must be done *after* the ia64_eoi().  For example, the keyboard softirq
+	 * handler needs to be able to wait for further keyboard interrupts, which can't
+	 * come through until ia64_eoi() has been done.
+	 */
+	irq_exit();
+	if ( wake_dom0 && current != dom0 ) 
+		domain_wake(dom0->exec_domain[0]);
+}
+#endif
+
+
 #ifdef CONFIG_HOTPLUG_CPU
 /*
  * This function emulates a interrupt processing when a cpu is about to be
