--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/gcc_intrin.h	2005-01-23 13:23:36.000000000 -0700
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/gcc_intrin.h	2004-08-25 19:28:13.000000000 -0600
@@ -92,6 +92,9 @@
 
 #define ia64_hint_pause 0
 
+#ifdef XEN
+#define ia64_hint(mode)	0
+#else
 #define ia64_hint(mode)						\
 ({								\
 	switch (mode) {						\
@@ -100,6 +103,7 @@
 		break;						\
 	}							\
 })
+#endif
 
 
 /* Integer values for mux1 instruction */
