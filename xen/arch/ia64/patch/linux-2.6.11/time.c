--- ../../linux-2.6.11/arch/ia64/kernel/time.c	2005-03-02 00:37:50.000000000 -0700
+++ arch/ia64/time.c	2005-05-02 11:19:29.000000000 -0600
@@ -29,6 +29,9 @@
 #include <asm/sal.h>
 #include <asm/sections.h>
 #include <asm/system.h>
+#ifdef XEN
+#include <linux/jiffies.h>	// not included by xen/sched.h
+#endif
 
 extern unsigned long wall_jiffies;
 
@@ -45,6 +48,7 @@
 
 #endif
 
+#ifndef XEN
 static struct time_interpolator itc_interpolator = {
 	.shift = 16,
 	.mask = 0xffffffffffffffffLL,
@@ -110,6 +114,7 @@
 	} while (time_after_eq(ia64_get_itc(), new_itm));
 	return IRQ_HANDLED;
 }
+#endif
 
 /*
  * Encapsulate access to the itm structure for SMP.
@@ -212,6 +217,7 @@
 					+ itc_freq/2)/itc_freq;
 
 	if (!(sal_platform_features & IA64_SAL_PLATFORM_FEATURE_ITC_DRIFT)) {
+#ifndef XEN
 		itc_interpolator.frequency = local_cpu_data->itc_freq;
 		itc_interpolator.drift = itc_drift;
 #ifdef CONFIG_SMP
@@ -228,12 +234,14 @@
 		if (!nojitter) itc_interpolator.jitter = 1;
 #endif
 		register_time_interpolator(&itc_interpolator);
+#endif
 	}
 
 	/* Setup the CPU local timer tick */
 	ia64_cpu_local_tick();
 }
 
+#ifndef XEN
 static struct irqaction timer_irqaction = {
 	.handler =	timer_interrupt,
 	.flags =	SA_INTERRUPT,
@@ -253,3 +261,4 @@
 	 */
 	set_normalized_timespec(&wall_to_monotonic, -xtime.tv_sec, -xtime.tv_nsec);
 }
+#endif
