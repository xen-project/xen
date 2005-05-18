--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/include/asm-ia64/processor.h	2005-03-01 23:37:58.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/include/asm-ia64/processor.h	2005-05-18 12:40:50.000000000 -0700
@@ -131,9 +131,166 @@
 	__u64 ri : 2;
 	__u64 ed : 1;
 	__u64 bn : 1;
+#ifdef CONFIG_VTI
+	__u64 ia : 1;
+	__u64 vm : 1;
+	__u64 reserved5 : 17;
+#else // CONFIG_VTI
 	__u64 reserved4 : 19;
+#endif // CONFIG_VTI
 };
 
+#ifdef  CONFIG_VTI
+/* vmx like above but expressed as bitfields for more efficient access: */
+typedef  union{
+    __u64 val;
+    struct{
+    	__u64 reserved0 : 1;
+	__u64 be : 1;
+    	__u64 up : 1;
+    	__u64 ac : 1;
+    	__u64 mfl : 1;
+    	__u64 mfh : 1;
+    	__u64 reserved1 : 7;
+    	__u64 ic : 1;
+    	__u64 i : 1;
+    	__u64 pk : 1;
+    	__u64 reserved2 : 1;
+    	__u64 dt : 1;
+    	__u64 dfl : 1;
+    	__u64 dfh : 1;
+    	__u64 sp : 1;
+    	__u64 pp : 1;
+    	__u64 di : 1;
+	__u64 si : 1;
+    	__u64 db : 1;
+    	__u64 lp : 1;
+    	__u64 tb : 1;
+    	__u64 rt : 1;
+    	__u64 reserved3 : 4;
+    	__u64 cpl : 2;
+    	__u64 is : 1;
+    	__u64 mc : 1;
+    	__u64 it : 1;
+    	__u64 id : 1;
+    	__u64 da : 1;
+    	__u64 dd : 1;
+    	__u64 ss : 1;
+    	__u64 ri : 2;
+    	__u64 ed : 1;
+    	__u64 bn : 1;
+    	__u64 reserved4 : 19;
+    };
+}   IA64_PSR;
+
+typedef union {
+    __u64 val;
+    struct {
+        __u64 code : 16;
+        __u64 vector : 8;
+        __u64 reserved1 : 8;
+        __u64 x : 1;
+        __u64 w : 1;
+        __u64 r : 1;
+        __u64 na : 1;
+        __u64 sp : 1;
+        __u64 rs : 1;
+        __u64 ir : 1;
+        __u64 ni : 1;
+        __u64 so : 1;
+        __u64 ei : 2;
+        __u64 ed : 1;
+        __u64 reserved2 : 20;
+    };
+}   ISR;
+
+
+typedef union {
+    __u64 val;
+    struct {
+        __u64 ve : 1;
+        __u64 reserved0 : 1;
+        __u64 size : 6;
+        __u64 vf : 1;
+        __u64 reserved1 : 6;
+        __u64 base : 49;
+    };
+}   PTA;
+
+typedef union {
+    __u64 val;
+    struct {
+        __u64  rv  : 16;
+        __u64  eid : 8;
+        __u64  id  : 8;
+        __u64  ig  : 32;
+    };
+} LID;
+
+typedef union{
+    __u64 val;
+    struct {
+        __u64 rv  : 3;
+        __u64 ir  : 1;
+        __u64 eid : 8;
+        __u64 id  : 8;
+        __u64 ib_base : 44;
+    };
+} ipi_a_t;
+
+typedef union{
+    __u64 val;
+    struct {
+        __u64 vector : 8;
+        __u64 dm  : 3;
+        __u64 ig  : 53;
+    };
+} ipi_d_t;
+
+
+#define IA64_ISR_CODE_MASK0     0xf
+#define IA64_UNIMPL_DADDR_FAULT     0x30
+#define IA64_UNIMPL_IADDR_TRAP      0x10
+#define IA64_RESERVED_REG_FAULT     0x30
+#define IA64_REG_NAT_CONSUMPTION_FAULT  0x10
+#define IA64_NAT_CONSUMPTION_FAULT  0x20
+#define IA64_PRIV_OP_FAULT      0x10
+
+/* indirect register type */
+enum {
+    IA64_CPUID,     /*  cpuid */
+    IA64_DBR,       /*  dbr */
+    IA64_IBR,       /*  ibr */
+    IA64_PKR,       /*  pkr */
+    IA64_PMC,       /*  pmc */
+    IA64_PMD,       /*  pmd */
+    IA64_RR         /*  rr */
+};
+
+/* instruction type */
+enum {
+    IA64_INST_TPA=1,
+    IA64_INST_TAK
+};
+
+/* Generate Mask
+ * Parameter:
+ *  bit -- starting bit
+ *  len -- how many bits
+ */
+#define MASK(bit,len)                   \
+({                              \
+        __u64    ret;                    \
+                                \
+        __asm __volatile("dep %0=-1, r0, %1, %2"    \
+                : "=r" (ret):                   \
+          "M" (bit),                    \
+          "M" (len) );                  \
+        ret;                            \
+})
+
+#endif  //  CONFIG_VTI
+
 /*
  * CPU type, hardware bug flags, and per-CPU state.  Frequently used
  * state comes earlier:
@@ -408,12 +565,16 @@
  */
 
 /* Return TRUE if task T owns the fph partition of the CPU we're running on. */
+#ifdef XEN
+#define ia64_is_local_fpu_owner(t) 0
+#else
 #define ia64_is_local_fpu_owner(t)								\
 ({												\
 	struct task_struct *__ia64_islfo_task = (t);						\
 	(__ia64_islfo_task->thread.last_fph_cpu == smp_processor_id()				\
 	 && __ia64_islfo_task == (struct task_struct *) ia64_get_kr(IA64_KR_FPU_OWNER));	\
 })
+#endif
 
 /* Mark task T as owning the fph partition of the CPU we're running on. */
 #define ia64_set_local_fpu_owner(t) do {						\
