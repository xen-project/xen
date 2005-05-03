--- ../../linux-2.6.11/include/linux/cpumask.h	2005-03-02 00:38:00.000000000 -0700
+++ include/asm-ia64/linux/cpumask.h	2005-04-28 13:21:20.000000000 -0600
@@ -342,7 +342,9 @@
  */
 
 extern cpumask_t cpu_possible_map;
+#ifndef XEN
 extern cpumask_t cpu_online_map;
+#endif
 extern cpumask_t cpu_present_map;
 
 #if NR_CPUS > 1
