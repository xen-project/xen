--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/include/asm-ia64/ide.h	2004-06-15 23:19:36.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/include/asm-ia64/ide.h	2004-08-25 19:28:13.000000000 -0600
@@ -64,6 +64,32 @@
 #define ide_init_default_irq(base)	ide_default_irq(base)
 #endif
 
+#ifdef XEN
+// this is moved to linux/ide.h in newer versions of linux
+typedef union {
+	unsigned all			: 8;	/* all of the bits together */
+	struct {
+		unsigned head		: 4;	/* always zeros here */
+		unsigned unit		: 1;	/* drive select number, 0 or 1 */
+		unsigned bit5		: 1;	/* always 1 */
+		unsigned lba		: 1;	/* using LBA instead of CHS */
+		unsigned bit7		: 1;	/* always 1 */
+	} b;
+} select_t;
+
+typedef union {
+	unsigned all			: 8;	/* all of the bits together */
+	struct {
+		unsigned bit0		: 1;
+		unsigned nIEN		: 1;	/* device INTRQ to host */
+		unsigned SRST		: 1;	/* host soft reset bit */
+		unsigned bit3		: 1;	/* ATA-2 thingy */
+		unsigned reserved456	: 3;
+		unsigned HOB		: 1;	/* 48-bit address ordering */
+	} b;
+} control_t;
+#endif
+
 #include <asm-generic/ide_iops.h>
 
 #endif /* __KERNEL__ */
