 wait.h |    6 ++++++
 1 files changed, 6 insertions(+)

Index: linux-2.6.11/include/linux/wait.h
===================================================================
--- linux-2.6.11.orig/include/linux/wait.h	2005-03-02 01:38:10.000000000 -0600
+++ linux-2.6.11/include/linux/wait.h	2005-03-19 15:00:23.691156973 -0600
@@ -136,7 +136,11 @@ static inline void __remove_wait_queue(w
 	list_del(&old->task_list);
 }
 
+#ifdef XEN
+void FASTCALL(__wake_up(struct task_struct *p));
+#else
 void FASTCALL(__wake_up(wait_queue_head_t *q, unsigned int mode, int nr, void *key));
+#endif
 extern void FASTCALL(__wake_up_locked(wait_queue_head_t *q, unsigned int mode));
 extern void FASTCALL(__wake_up_sync(wait_queue_head_t *q, unsigned int mode, int nr));
 void FASTCALL(__wake_up_bit(wait_queue_head_t *, void *, int));
@@ -147,6 +151,7 @@ int FASTCALL(out_of_line_wait_on_bit(voi
 int FASTCALL(out_of_line_wait_on_bit_lock(void *, int, int (*)(void *), unsigned));
 wait_queue_head_t *FASTCALL(bit_waitqueue(void *, int));
 
+#ifndef XEN
 #define wake_up(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 1, NULL)
 #define wake_up_nr(x, nr)		__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, nr, NULL)
 #define wake_up_all(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 0, NULL)
@@ -155,6 +160,7 @@ wait_queue_head_t *FASTCALL(bit_waitqueu
 #define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
 #define	wake_up_locked(x)		__wake_up_locked((x), TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE)
 #define wake_up_interruptible_sync(x)   __wake_up_sync((x),TASK_INTERRUPTIBLE, 1)
+#endif
 
 #define __wait_event(wq, condition) 					\
 do {									\
