--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/wait.h	2004-06-15 23:19:31.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/linux/wait.h	2004-08-25 19:28:13.000000000 -0600
@@ -104,10 +104,15 @@
 	list_del(&old->task_list);
 }
 
+#ifdef XEN
+void FASTCALL(__wake_up(struct task_struct *p));
+#else
 void FASTCALL(__wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key));
+#endif
 extern void FASTCALL(__wake_up_locked(wait_queue_head_t *q, unsigned int mode));
 extern void FASTCALL(__wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr));
 
+#ifndef XEN
 #define wake_up(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 1, NULL)
 #define wake_up_nr(x, nr)		__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, nr, NULL)
 #define wake_up_all(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 0, NULL)
@@ -117,6 +122,7 @@
 #define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
 #define	wake_up_locked(x)		__wake_up_locked((x), TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE)
 #define wake_up_interruptible_sync(x)   __wake_up_sync((x),TASK_INTERRUPTIBLE, 1)
+#endif
 
 #define __wait_event(wq, condition) 					\
 do {									\
