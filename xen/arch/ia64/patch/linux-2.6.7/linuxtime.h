--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/time.h	2004-06-15 23:19:37.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/xen/linuxtime.h	2004-11-15 17:42:04.000000000 -0700
@@ -1,6 +1,11 @@
 #ifndef _LINUX_TIME_H
 #define _LINUX_TIME_H
 
+#ifdef XEN
+typedef	s64 time_t;
+typedef	s64 suseconds_t;
+#endif
+
 #include <asm/param.h>
 #include <linux/types.h>
 
@@ -25,7 +30,9 @@
 #ifdef __KERNEL__
 
 #include <linux/spinlock.h>
+#ifndef XEN
 #include <linux/seqlock.h>
+#endif
 #include <linux/timex.h>
 #include <asm/div64.h>
 #ifndef div_long_long_rem
@@ -322,7 +329,9 @@
 
 extern struct timespec xtime;
 extern struct timespec wall_to_monotonic;
+#ifndef XEN
 extern seqlock_t xtime_lock;
+#endif
 
 static inline unsigned long get_seconds(void)
 { 
