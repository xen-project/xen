--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/init_task.h	2004-06-15 23:18:57.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/linux/init_task.h	2004-11-15 17:06:20.000000000 -0700
@@ -31,6 +31,18 @@
 	.max_reqs	= ~0U,				\
 }
 
+#ifdef XEN
+#define INIT_MM(name) \
+{			 					\
+	.mm_rb		= RB_ROOT,				\
+	.pgd		= swapper_pg_dir, 			\
+	.mm_users	= ATOMIC_INIT(2), 			\
+	.mm_count	= ATOMIC_INIT(1), 			\
+	.page_table_lock =  SPIN_LOCK_UNLOCKED, 		\
+	.mmlist		= LIST_HEAD_INIT(name.mmlist),		\
+	.cpu_vm_mask	= CPU_MASK_ALL,				\
+}
+#else
 #define INIT_MM(name) \
 {			 					\
 	.mm_rb		= RB_ROOT,				\
@@ -43,6 +55,7 @@
 	.cpu_vm_mask	= CPU_MASK_ALL,				\
 	.default_kioctx = INIT_KIOCTX(name.default_kioctx, name),	\
 }
+#endif
 
 #define INIT_SIGNALS(sig) {	\
 	.count		= ATOMIC_INIT(1), 		\
@@ -64,6 +77,15 @@
  *  INIT_TASK is used to set up the first task table, touch at
  * your own risk!. Base=0, limit=0x1fffff (=2MB)
  */
+#ifdef XEN
+#define INIT_TASK(tsk) \
+{							\
+	/*processor:	0,*/				\
+	/*domain_id:	IDLE_DOMAIN_ID,*/		\
+	/*domain_flags:	DOMF_idle_domain,*/		\
+	refcnt:		ATOMIC_INIT(1)			\
+}
+#else
 #define INIT_TASK(tsk)	\
 {									\
 	.state		= 0,						\
@@ -113,6 +135,7 @@
 	.switch_lock	= SPIN_LOCK_UNLOCKED,				\
 	.journal_info	= NULL,						\
 }
+#endif
 
 
 
