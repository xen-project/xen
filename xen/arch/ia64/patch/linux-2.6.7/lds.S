--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/vmlinux.lds.S	2004-06-15 23:19:52.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/xen.lds.S	2004-08-25 19:28:12.000000000 -0600
@@ -11,12 +11,14 @@
 OUTPUT_FORMAT("elf64-ia64-little")
 OUTPUT_ARCH(ia64)
 ENTRY(phys_start)
+#ifndef XEN
 jiffies = jiffies_64;
 PHDRS {
   code   PT_LOAD;
   percpu PT_LOAD;
   data   PT_LOAD;
 }
+#endif
 SECTIONS
 {
   /* Sections to be discarded */
