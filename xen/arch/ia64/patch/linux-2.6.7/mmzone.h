--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/mmzone.h	2004-06-15 23:19:36.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/linux/mmzone.h	2004-08-25 19:28:13.000000000 -0600
@@ -185,7 +185,11 @@
 	char			*name;
 	unsigned long		spanned_pages;	/* total size, including holes */
 	unsigned long		present_pages;	/* amount of memory (excluding holes) */
+#ifdef XEN
+};
+#else
 } ____cacheline_maxaligned_in_smp;
+#endif
 
 
 /*
