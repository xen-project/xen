 time.h |    9 +++++++++
 1 files changed, 9 insertions(+)

Index: linux-2.6.11/include/linux/time.h
===================================================================
--- linux-2.6.11.orig/include/linux/time.h	2005-03-02 01:38:12.000000000 -0600
+++ linux-2.6.11/include/linux/time.h	2005-03-19 13:46:27.987225234 -0600
@@ -1,11 +1,18 @@
 #ifndef _LINUX_TIME_H
 #define _LINUX_TIME_H
 
+#ifdef XEN
+typedef	s64 time_t;
+typedef	s64 suseconds_t;
+#endif
+
 #include <linux/types.h>
 
+#ifndef XEN
 #ifdef __KERNEL__
 #include <linux/seqlock.h>
 #endif
+#endif
 
 #ifndef _STRUCT_TIMESPEC
 #define _STRUCT_TIMESPEC
@@ -80,7 +87,9 @@ mktime (unsigned int year, unsigned int 
 
 extern struct timespec xtime;
 extern struct timespec wall_to_monotonic;
+#ifndef XEN
 extern seqlock_t xtime_lock;
+#endif
 
 static inline unsigned long get_seconds(void)
 { 
