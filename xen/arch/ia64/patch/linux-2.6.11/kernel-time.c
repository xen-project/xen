 time.c |    7 ++++++-
 1 files changed, 6 insertions(+), 1 deletion(-)

Index: linux-2.6.11/kernel/time.c
===================================================================
--- linux-2.6.11.orig/kernel/time.c	2005-03-02 01:37:50.000000000 -0600
+++ linux-2.6.11/kernel/time.c	2005-03-19 14:56:40.767870674 -0600
@@ -495,6 +495,7 @@ void getnstimeofday (struct timespec *tv
 	tv->tv_nsec = nsec;
 }
 
+#ifndef XEN
 int do_settimeofday (struct timespec *tv)
 {
 	time_t wtm_sec, sec = tv->tv_sec;
@@ -503,7 +504,9 @@ int do_settimeofday (struct timespec *tv
 	if ((unsigned long)tv->tv_nsec >= NSEC_PER_SEC)
 		return -EINVAL;
 
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 	write_seqlock_irq(&xtime_lock);
+#endif
 	{
 		/*
 		 * This is revolting. We need to set "xtime" correctly. However, the value
@@ -525,7 +528,9 @@ int do_settimeofday (struct timespec *tv
 		time_esterror = NTP_PHASE_LIMIT;
 		time_interpolator_reset();
 	}
+#ifdef TURN_ME_OFF_FOR_NOW_IA64_XEN
 	write_sequnlock_irq(&xtime_lock);
+#endif
 	clock_was_set();
 	return 0;
 }
@@ -552,7 +557,7 @@ void do_gettimeofday (struct timeval *tv
 }
 
 EXPORT_SYMBOL(do_gettimeofday);
-
+#endif
 
 #else
 /*
