--- /home/adsharma/disk2/xen-ia64/test3.bk/xen/../../linux-2.6.11/arch/ia64/kernel/entry.h	2005-03-01 23:38:07.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/test3.bk/xen/arch/ia64/entry.h	2005-05-18 14:00:53.000000000 -0700
@@ -7,6 +7,12 @@
 #define PRED_LEAVE_SYSCALL	1 /* TRUE iff leave from syscall */
 #define PRED_KERNEL_STACK	2 /* returning to kernel-stacks? */
 #define PRED_USER_STACK		3 /* returning to user-stacks? */
+#ifdef CONFIG_VTI
+#define PRED_EMUL		2 /* Need to save r4-r7 for inst emulation */
+#define PRED_NON_EMUL		3 /* No need to save r4-r7 for normal path */
+#define PRED_BN0		6 /* Guest is in bank 0 */
+#define PRED_BN1		7 /* Guest is in bank 1 */
+#endif // CONFIG_VTI
 #define PRED_SYSCALL		4 /* inside a system call? */
 #define PRED_NON_SYSCALL	5 /* complement of PRED_SYSCALL */
 
@@ -17,12 +23,21 @@
 # define pLvSys		PASTE(p,PRED_LEAVE_SYSCALL)
 # define pKStk		PASTE(p,PRED_KERNEL_STACK)
 # define pUStk		PASTE(p,PRED_USER_STACK)
+#ifdef CONFIG_VTI
+# define pEml		PASTE(p,PRED_EMUL)
+# define pNonEml	PASTE(p,PRED_NON_EMUL)
+# define pBN0		PASTE(p,PRED_BN0)
+# define pBN1		PASTE(p,PRED_BN1)
+#endif // CONFIG_VTI
 # define pSys		PASTE(p,PRED_SYSCALL)
 # define pNonSys	PASTE(p,PRED_NON_SYSCALL)
 #endif
 
 #define PT(f)		(IA64_PT_REGS_##f##_OFFSET)
 #define SW(f)		(IA64_SWITCH_STACK_##f##_OFFSET)
+#ifdef CONFIG_VTI
+#define VPD(f)      (VPD_##f##_START_OFFSET)
+#endif // CONFIG_VTI
 
 #define PT_REGS_SAVES(off)			\
 	.unwabi 3, 'i';				\
