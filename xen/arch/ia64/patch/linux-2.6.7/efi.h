--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/linux/efi.h	2004-06-15 23:20:03.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/linux/efi.h	2004-08-25 19:28:13.000000000 -0600
@@ -15,8 +15,10 @@
 #include <linux/string.h>
 #include <linux/time.h>
 #include <linux/types.h>
+#ifndef XEN
 #include <linux/proc_fs.h>
 #include <linux/rtc.h>
+#endif
 #include <linux/ioport.h>
 
 #include <asm/page.h>
