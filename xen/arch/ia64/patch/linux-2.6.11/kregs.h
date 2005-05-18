--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/include/asm-ia64/kregs.h	2005-03-01 23:37:49.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/include/asm-ia64/kregs.h	2005-05-18 12:40:50.000000000 -0700
@@ -29,8 +29,20 @@
  */
 #define IA64_TR_KERNEL		0	/* itr0, dtr0: maps kernel image (code & data) */
 #define IA64_TR_PALCODE		1	/* itr1: maps PALcode as required by EFI */
+#ifdef CONFIG_VTI
+#define IA64_TR_XEN_IN_DOM	6	/* itr6, dtr6: Double mapping for xen image in domain space */
+#endif // CONFIG_VTI
 #define IA64_TR_PERCPU_DATA	1	/* dtr1: percpu data */
 #define IA64_TR_CURRENT_STACK	2	/* dtr2: maps kernel's memory- & register-stacks */
+#ifdef XEN
+#define IA64_TR_SHARED_INFO	3	/* dtr3: page shared with domain */
+#define	IA64_TR_VHPT		4	/* dtr4: vhpt */
+#ifdef CONFIG_VTI
+#define IA64_TR_VHPT_IN_DOM	5	/* dtr5: Double mapping for vhpt table in domain space */
+#define IA64_TR_RR7_SWITCH_STUB	7	/* dtr7: mapping for rr7 switch stub */
+#define IA64_TEMP_PHYSICAL	8	/* itr8, dtr8: temp mapping for guest physical memory 256M */
+#endif // CONFIG_VTI
+#endif
 
 /* Processor status register bits: */
 #define IA64_PSR_BE_BIT		1
@@ -66,6 +78,9 @@
 #define IA64_PSR_ED_BIT		43
 #define IA64_PSR_BN_BIT		44
 #define IA64_PSR_IA_BIT		45
+#ifdef CONFIG_VTI
+#define IA64_PSR_VM_BIT		46
+#endif // CONFIG_VTI
 
 /* A mask of PSR bits that we generally don't want to inherit across a clone2() or an
    execve().  Only list flags here that need to be cleared/set for BOTH clone2() and
@@ -107,6 +122,9 @@
 #define IA64_PSR_ED	(__IA64_UL(1) << IA64_PSR_ED_BIT)
 #define IA64_PSR_BN	(__IA64_UL(1) << IA64_PSR_BN_BIT)
 #define IA64_PSR_IA	(__IA64_UL(1) << IA64_PSR_IA_BIT)
+#ifdef CONFIG_VTI
+#define IA64_PSR_VM	(__IA64_UL(1) << IA64_PSR_VM_BIT)
+#endif // CONFIG_VTI
 
 /* User mask bits: */
 #define IA64_PSR_UM	(IA64_PSR_BE | IA64_PSR_UP | IA64_PSR_AC | IA64_PSR_MFL | IA64_PSR_MFH)
@@ -160,4 +178,21 @@
 #define IA64_ISR_CODE_LFETCH	4
 #define IA64_ISR_CODE_PROBEF	5
 
+#ifdef CONFIG_VTI
+/* Interruption Function State */
+#define IA64_IFS_V_BIT		63
+#define IA64_IFS_V	(__IA64_UL(1) << IA64_IFS_V_BIT)
+
+/* Page Table Address */
+#define IA64_PTA_VE_BIT 0
+#define IA64_PTA_SIZE_BIT 2
+#define IA64_PTA_VF_BIT 8
+#define IA64_PTA_BASE_BIT 15
+
+#define IA64_PTA_VE     (__IA64_UL(1) << IA64_PTA_VE_BIT)
+#define IA64_PTA_SIZE   (__IA64_UL(0x3f) << IA64_PTA_SIZE_BIT)
+#define IA64_PTA_VF     (__IA64_UL(1) << IA64_PTA_VF_BIT)
+#define IA64_PTA_BASE   (__IA64_UL(0) - ((__IA64_UL(1) << IA64_PTA_BASE_BIT)))
+#endif // CONFIG_VTI
+
 #endif /* _ASM_IA64_kREGS_H */
