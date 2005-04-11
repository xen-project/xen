 vmlinux.lds.S |    2 ++
 1 files changed, 2 insertions(+)

Index: linux-2.6.11/arch/ia64/kernel/vmlinux.lds.S
===================================================================
--- linux-2.6.11.orig/arch/ia64/kernel/vmlinux.lds.S	2005-03-02 01:38:25.000000000 -0600
+++ linux-2.6.11/arch/ia64/kernel/vmlinux.lds.S	2005-03-19 13:44:28.746368232 -0600
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
