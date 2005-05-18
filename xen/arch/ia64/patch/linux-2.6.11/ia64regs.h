--- /home/adsharma/disk2/xen-ia64/test3.bk/xen/../../linux-2.6.11/include/asm-ia64/ia64regs.h	2005-03-01 23:38:07.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/test3.bk/xen/include/asm-ia64/ia64regs.h	2005-05-18 14:00:53.000000000 -0700
@@ -87,6 +87,35 @@
 #define _IA64_REG_CR_LRR0	4176
 #define _IA64_REG_CR_LRR1	4177
 
+#ifdef  CONFIG_VTI
+#define IA64_REG_CR_DCR   0
+#define IA64_REG_CR_ITM   1
+#define IA64_REG_CR_IVA   2
+#define IA64_REG_CR_PTA   8
+#define IA64_REG_CR_IPSR  16
+#define IA64_REG_CR_ISR   17
+#define IA64_REG_CR_IIP   19
+#define IA64_REG_CR_IFA   20
+#define IA64_REG_CR_ITIR  21
+#define IA64_REG_CR_IIPA  22
+#define IA64_REG_CR_IFS   23
+#define IA64_REG_CR_IIM   24
+#define IA64_REG_CR_IHA   25
+#define IA64_REG_CR_LID   64
+#define IA64_REG_CR_IVR   65
+#define IA64_REG_CR_TPR   66
+#define IA64_REG_CR_EOI   67
+#define IA64_REG_CR_IRR0  68
+#define IA64_REG_CR_IRR1  69
+#define IA64_REG_CR_IRR2  70
+#define IA64_REG_CR_IRR3  71
+#define IA64_REG_CR_ITV   72
+#define IA64_REG_CR_PMV   73
+#define IA64_REG_CR_CMCV  74
+#define IA64_REG_CR_LRR0  80
+#define IA64_REG_CR_LRR1  81
+#endif  //  CONFIG_VTI
+
 /* Indirect Registers for getindreg() and setindreg() */
 
 #define _IA64_REG_INDR_CPUID	9000	/* getindreg only */
