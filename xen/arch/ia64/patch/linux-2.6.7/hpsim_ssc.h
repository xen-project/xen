--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/hp/sim/hpsim_ssc.h	2004-06-15 23:19:43.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/hpsim_ssc.h	2004-08-29 01:04:23.000000000 -0600
@@ -33,4 +33,23 @@
  */
 extern long ia64_ssc (long arg0, long arg1, long arg2, long arg3, int nr);
 
+#ifdef XEN
+/* Note: These are declared in linux/arch/ia64/hp/sim/simscsi.c but belong
+ * in linux/include/asm-ia64/hpsim_ssc.h, hence their addition here */
+#define SSC_OPEN			50
+#define SSC_CLOSE			51
+#define SSC_READ			52
+#define SSC_WRITE			53
+#define SSC_GET_COMPLETION		54
+#define SSC_WAIT_COMPLETION		55
+
+#define SSC_WRITE_ACCESS		2
+#define SSC_READ_ACCESS			1
+
+struct ssc_disk_req {
+	unsigned long addr;
+	unsigned long len;
+};
+#endif
+
 #endif /* _IA64_PLATFORM_HPSIM_SSC_H */
