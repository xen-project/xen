--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/init_task.c	2004-06-15 23:20:26.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/init_task.c	2004-08-27 00:06:35.000000000 -0600
@@ -15,10 +15,12 @@
 #include <asm/uaccess.h>
 #include <asm/pgtable.h>
 
+#ifndef XEN
 static struct fs_struct init_fs = INIT_FS;
 static struct files_struct init_files = INIT_FILES;
 static struct signal_struct init_signals = INIT_SIGNALS(init_signals);
 static struct sighand_struct init_sighand = INIT_SIGHAND(init_sighand);
+#endif
 struct mm_struct init_mm = INIT_MM(init_mm);
 
 EXPORT_SYMBOL(init_mm);
@@ -33,13 +35,19 @@
 
 union {
 	struct {
+#ifdef XEN
+		struct domain task;
+#else
 		struct task_struct task;
 		struct thread_info thread_info;
+#endif
 	} s;
 	unsigned long stack[KERNEL_STACK_SIZE/sizeof (unsigned long)];
 } init_task_mem asm ("init_task") __attribute__((section(".data.init_task"))) = {{
 	.task =		INIT_TASK(init_task_mem.s.task),
+#ifndef XEN
 	.thread_info =	INIT_THREAD_INFO(init_task_mem.s.task)
+#endif
 }};
 
 EXPORT_SYMBOL(init_task);
