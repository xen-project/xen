--- ../../linux-2.6.7/arch/ia64/kernel/time.c	2004-06-15 23:19:01.000000000 -0600
+++ arch/ia64/time.c	2005-03-09 13:22:52.000000000 -0700
@@ -10,16 +10,22 @@
  */
 #include <linux/config.h>
 
+#ifndef XEN
 #include <linux/cpu.h>
+#endif
 #include <linux/init.h>
 #include <linux/kernel.h>
 #include <linux/module.h>
+#ifndef XEN
 #include <linux/profile.h>
+#endif
 #include <linux/sched.h>
 #include <linux/time.h>
 #include <linux/interrupt.h>
 #include <linux/efi.h>
+#ifndef XEN
 #include <linux/profile.h>
+#endif
 #include <linux/timex.h>
 
 #include <asm/machvec.h>
@@ -29,6 +35,9 @@
 #include <asm/sal.h>
 #include <asm/sections.h>
 #include <asm/system.h>
+#ifdef XEN
+#include <asm/ia64_int.h>
+#endif
 
 extern unsigned long wall_jiffies;
 
@@ -45,6 +54,59 @@
 
 #endif
 
+#ifdef XEN
+volatile unsigned long last_nsec_offset;
+extern rwlock_t xtime_lock;
+unsigned long cpu_khz;  /* Detected as we calibrate the TSC */
+static s_time_t        stime_irq;       /* System time at last 'time update' */
+
+static inline u64 get_time_delta(void)
+{
+	return ia64_get_itc();
+}
+
+s_time_t get_s_time(void)
+{
+    s_time_t now;
+    unsigned long flags;
+
+    read_lock_irqsave(&xtime_lock, flags);
+
+    now = stime_irq + get_time_delta();
+
+    /* Ensure that the returned system time is monotonically increasing. */
+    {
+        static s_time_t prev_now = 0;
+        if ( unlikely(now < prev_now) )
+            now = prev_now;
+        prev_now = now;
+    }
+
+    read_unlock_irqrestore(&xtime_lock, flags);
+
+    return now; 
+}
+
+void update_dom_time(struct exec_domain *ed)
+{
+// FIXME: implement this?
+//	printf("update_dom_time: called, not implemented, skipping\n");
+	return;
+}
+
+/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
+void do_settime(unsigned long secs, unsigned long usecs, u64 system_time_base)
+{
+// FIXME: Should this be do_settimeofday (from linux)???
+	printf("do_settime: called, not implemented, stopping\n");
+	dummy();
+}
+#endif
+
+#if 0	/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
+#endif	/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
+
+#ifndef XEN
 static void
 itc_reset (void)
 {
@@ -80,12 +142,15 @@
 	return (elapsed_cycles*local_cpu_data->nsec_per_cyc) >> IA64_NSEC_PER_CYC_SHIFT;
 }
 
+#ifndef XEN
 static struct time_interpolator itc_interpolator = {
 	.get_offset =	itc_get_offset,
 	.update =	itc_update,
 	.reset =	itc_reset
 };
+#endif
 
+#ifndef XEN
 int
 do_settimeofday (struct timespec *tv)
 {
@@ -95,7 +160,9 @@
 	if ((unsigned long)tv->tv_nsec >= NSEC_PER_SEC)
 		return -EINVAL;
 
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 	write_seqlock_irq(&xtime_lock);
+#endif
 	{
 		/*
 		 * This is revolting. We need to set "xtime" correctly. However, the value
@@ -117,12 +184,15 @@
 		time_esterror = NTP_PHASE_LIMIT;
 		time_interpolator_reset();
 	}
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 	write_sequnlock_irq(&xtime_lock);
+#endif
 	clock_was_set();
 	return 0;
 }
 
 EXPORT_SYMBOL(do_settimeofday);
+#endif
 
 void
 do_gettimeofday (struct timeval *tv)
@@ -185,6 +255,7 @@
 }
 
 EXPORT_SYMBOL(do_gettimeofday);
+#endif
 
 /*
  * The profiling function is SMP safe. (nothing can mess
@@ -195,6 +266,9 @@
 static inline void
 ia64_do_profile (struct pt_regs * regs)
 {
+#ifdef XEN
+}
+#else
 	unsigned long ip, slot;
 	extern cpumask_t prof_cpu_mask;
 
@@ -231,24 +305,89 @@
 		ip = prof_len-1;
 	atomic_inc((atomic_t *)&prof_buffer[ip]);
 }
+#endif
+
+#ifdef XEN
+unsigned long domain0_ready = 0;	// FIXME (see below)
+#define typecheck(a,b)	1
+/* FROM linux/include/linux/jiffies.h */
+/*
+ *	These inlines deal with timer wrapping correctly. You are 
+ *	strongly encouraged to use them
+ *	1. Because people otherwise forget
+ *	2. Because if the timer wrap changes in future you won't have to
+ *	   alter your driver code.
+ *
+ * time_after(a,b) returns true if the time a is after time b.
+ *
+ * Do this with "<0" and ">=0" to only test the sign of the result. A
+ * good compiler would generate better code (and a really good compiler
+ * wouldn't care). Gcc is currently neither.
+ */
+#define time_after(a,b)		\
+	(typecheck(unsigned long, a) && \
+	 typecheck(unsigned long, b) && \
+	 ((long)(b) - (long)(a) < 0))
+#define time_before(a,b)	time_after(b,a)
+
+#define time_after_eq(a,b)	\
+	(typecheck(unsigned long, a) && \
+	 typecheck(unsigned long, b) && \
+	 ((long)(a) - (long)(b) >= 0))
+#define time_before_eq(a,b)	time_after_eq(b,a)
+#endif
 
 static irqreturn_t
 timer_interrupt (int irq, void *dev_id, struct pt_regs *regs)
 {
 	unsigned long new_itm;
 
+#ifndef XEN
 	if (unlikely(cpu_is_offline(smp_processor_id()))) {
 		return IRQ_HANDLED;
 	}
+#endif
+#ifdef XEN
+	if (current->domain == dom0) {
+		// FIXME: there's gotta be a better way of doing this...
+		// We have to ensure that domain0 is launched before we
+		// call vcpu_timer_expired on it
+		//domain0_ready = 1; // moved to xensetup.c
+	}
+	if (domain0_ready && vcpu_timer_expired(dom0->exec_domain[0])) {
+		vcpu_pend_timer(dom0->exec_domain[0]);
+		vcpu_set_next_timer(dom0->exec_domain[0]);
+		domain_wake(dom0->exec_domain[0]);
+	}
+	if (!is_idle_task(current->domain) && current->domain != dom0) {
+		if (vcpu_timer_expired(current)) {
+			vcpu_pend_timer(current);
+			// ensure another timer interrupt happens even if domain doesn't
+			vcpu_set_next_timer(current);
+			domain_wake(current);
+		}
+	}
+	raise_actimer_softirq();
+#endif
 
+#ifndef XEN
 	platform_timer_interrupt(irq, dev_id, regs);
+#endif
 
 	new_itm = local_cpu_data->itm_next;
 
 	if (!time_after(ia64_get_itc(), new_itm))
+#ifdef XEN
+		return;
+#else
 		printk(KERN_ERR "Oops: timer tick before it's due (itc=%lx,itm=%lx)\n",
 		       ia64_get_itc(), new_itm);
+#endif
 
+#ifdef XEN
+//	printf("GOT TO HERE!!!!!!!!!!!\n");
+	//while(1);
+#endif
 	ia64_do_profile(regs);
 
 	while (1) {
@@ -269,10 +408,16 @@
 			 * another CPU. We need to avoid to SMP race by acquiring the
 			 * xtime_lock.
 			 */
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 			write_seqlock(&xtime_lock);
+#endif
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 			do_timer(regs);
+#endif
 			local_cpu_data->itm_next = new_itm;
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 			write_sequnlock(&xtime_lock);
+#endif
 		} else
 			local_cpu_data->itm_next = new_itm;
 
@@ -292,7 +437,12 @@
 		 */
 		while (!time_after(new_itm, ia64_get_itc() + local_cpu_data->itm_delta/2))
 			new_itm += local_cpu_data->itm_delta;
+//#ifdef XEN
+//		vcpu_set_next_timer(current);
+//#else
+//printf("***** timer_interrupt: Setting itm to %lx\n",new_itm);
 		ia64_set_itm(new_itm);
+//#endif
 		/* double check, in case we got hit by a (slow) PMI: */
 	} while (time_after_eq(ia64_get_itc(), new_itm));
 	return IRQ_HANDLED;
@@ -307,6 +457,7 @@
 	int cpu = smp_processor_id();
 	unsigned long shift = 0, delta;
 
+printf("ia64_cpu_local_tick: about to call ia64_set_itv\n");
 	/* arrange for the cycle counter to generate a timer interrupt: */
 	ia64_set_itv(IA64_TIMER_VECTOR);
 
@@ -320,6 +471,7 @@
 		shift = (2*(cpu - hi) + 1) * delta/hi/2;
 	}
 	local_cpu_data->itm_next = ia64_get_itc() + delta + shift;
+printf("***** ia64_cpu_local_tick: Setting itm to %lx\n",local_cpu_data->itm_next);
 	ia64_set_itm(local_cpu_data->itm_next);
 }
 
@@ -335,6 +487,7 @@
 	 * frequency and then a PAL call to determine the frequency ratio between the ITC
 	 * and the base frequency.
 	 */
+
 	status = ia64_sal_freq_base(SAL_FREQ_BASE_PLATFORM,
 				    &platform_base_freq, &platform_base_drift);
 	if (status != 0) {
@@ -384,9 +537,11 @@
 					+ itc_freq/2)/itc_freq;
 
 	if (!(sal_platform_features & IA64_SAL_PLATFORM_FEATURE_ITC_DRIFT)) {
+#ifndef XEN
 		itc_interpolator.frequency = local_cpu_data->itc_freq;
 		itc_interpolator.drift = itc_drift;
 		register_time_interpolator(&itc_interpolator);
+#endif
 	}
 
 	/* Setup the CPU local timer tick */
@@ -395,7 +550,9 @@
 
 static struct irqaction timer_irqaction = {
 	.handler =	timer_interrupt,
+#ifndef XEN
 	.flags =	SA_INTERRUPT,
+#endif
 	.name =		"timer"
 };
 
@@ -403,12 +560,16 @@
 time_init (void)
 {
 	register_percpu_irq(IA64_TIMER_VECTOR, &timer_irqaction);
+#ifndef XEN
 	efi_gettimeofday(&xtime);
+#endif
 	ia64_init_itm();
 
+#ifndef XEN
 	/*
 	 * Initialize wall_to_monotonic such that adding it to xtime will yield zero, the
 	 * tv_nsec field must be normalized (i.e., 0 <= nsec < NSEC_PER_SEC).
 	 */
 	set_normalized_timespec(&wall_to_monotonic, -xtime.tv_sec, -xtime.tv_nsec);
+#endif
 }
