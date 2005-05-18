--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/include/asm-ia64/system.h	2005-03-01 23:38:07.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/include/asm-ia64/system.h	2005-05-18 12:40:50.000000000 -0700
@@ -24,8 +24,22 @@
  * 0xa000000000000000+2*PERCPU_PAGE_SIZE
  * - 0xa000000000000000+3*PERCPU_PAGE_SIZE remain unmapped (guard page)
  */
+#ifdef XEN
+#ifdef CONFIG_VTI
+#define XEN_VIRT_SPACE_LOW	 0xe800000000000000
+#define XEN_VIRT_SPACE_HIGH	 0xf800000000000000	
+/* This is address to mapping rr7 switch stub, in region 5 */
+#define XEN_RR7_SWITCH_STUB	 0xb700000000000000
+#endif // CONFIG_VTI
+
+#define KERNEL_START		 0xf000000004000000
+#define PERCPU_ADDR		 0xf100000000000000-PERCPU_PAGE_SIZE
+#define SHAREDINFO_ADDR		 0xf100000000000000
+#define VHPT_ADDR		 0xf200000000000000
+#else
 #define KERNEL_START		 __IA64_UL_CONST(0xa000000100000000)
 #define PERCPU_ADDR		(-PERCPU_PAGE_SIZE)
+#endif
 
 #ifndef __ASSEMBLY__
 
@@ -205,6 +219,9 @@
  * ia64_ret_from_syscall_clear_r8.
  */
 extern struct task_struct *ia64_switch_to (void *next_task);
+#ifdef CONFIG_VTI
+extern struct task_struct *vmx_ia64_switch_to (void *next_task);
+#endif // CONFIG_VTI
 
 struct task_struct;
 
@@ -218,10 +235,32 @@
 # define PERFMON_IS_SYSWIDE() (0)
 #endif
 
+#ifdef XEN
+#define IA64_HAS_EXTRA_STATE(t) 0
+#else
 #define IA64_HAS_EXTRA_STATE(t)							\
 	((t)->thread.flags & (IA64_THREAD_DBG_VALID|IA64_THREAD_PM_VALID)	\
 	 || IS_IA32_PROCESS(ia64_task_regs(t)) || PERFMON_IS_SYSWIDE())
+#endif
 
+#ifdef CONFIG_VTI
+#define __switch_to(prev,next,last) do {	\
+       if (VMX_DOMAIN(prev))                   \
+               vmx_save_state(prev);           \
+       else {                                  \
+               if (IA64_HAS_EXTRA_STATE(prev)) \
+                       ia64_save_extra(prev);  \
+       }                                       \
+       if (VMX_DOMAIN(next))                   \
+               vmx_load_state(next);           \
+       else {                                  \
+               if (IA64_HAS_EXTRA_STATE(next)) \
+                       ia64_save_extra(next);  \
+       }                                       \
+       ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next); \
+       (last) = vmx_ia64_switch_to((next));        \
+} while (0)
+#else // CONFIG_VTI
 #define __switch_to(prev,next,last) do {							 \
 	if (IA64_HAS_EXTRA_STATE(prev))								 \
 		ia64_save_extra(prev);								 \
@@ -230,6 +269,7 @@
 	ia64_psr(ia64_task_regs(next))->dfh = !ia64_is_local_fpu_owner(next);			 \
 	(last) = ia64_switch_to((next));							 \
 } while (0)
+#endif // CONFIG_VTI
 
 #ifdef CONFIG_SMP
 /*
