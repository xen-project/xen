--- /home/adsharma/disk2/xen-ia64/test3.bk/xen/../../linux-2.6.11/include/asm-ia64/pal.h	2005-03-01 23:38:13.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/test3.bk/xen/include/asm-ia64/pal.h	2005-05-18 14:00:53.000000000 -0700
@@ -1559,6 +1559,9 @@
 	return iprv.status;
 }
 
+#ifdef CONFIG_VTI
+#include <asm/vmx_pal.h>
+#endif // CONFIG_VTI
 #endif /* __ASSEMBLY__ */
 
 #endif /* _ASM_IA64_PAL_H */
