--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/arch/ia64/kernel/unaligned.c	2004-06-15 23:20:03.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/unaligned.c	2004-08-25 19:28:12.000000000 -0600
@@ -15,8 +15,10 @@
  */
 #include <linux/kernel.h>
 #include <linux/sched.h>
+#ifndef XEN
 #include <linux/smp_lock.h>
 #include <linux/tty.h>
+#endif
 
 #include <asm/intrinsics.h>
 #include <asm/processor.h>
@@ -24,7 +26,16 @@
 #include <asm/uaccess.h>
 #include <asm/unaligned.h>
 
+#ifdef XEN
+#define	ia64_peek(x...)	printk("ia64_peek: called, not implemented\n")
+#define	ia64_poke(x...)	printk("ia64_poke: called, not implemented\n")
+#define	ia64_sync_fph(x...) printk("ia64_sync_fph: called, not implemented\n")
+#define	ia64_flush_fph(x...) printk("ia64_flush_fph: called, not implemented\n")
+#define	die_if_kernel(x...) printk("die_if_kernel: called, not implemented\n")
+#define jiffies 0
+#else
 extern void die_if_kernel(char *str, struct pt_regs *regs, long err) __attribute__ ((noreturn));
+#endif
 
 #undef DEBUG_UNALIGNED_TRAP
 
@@ -437,7 +448,11 @@
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 setreg (unsigned long regnum, unsigned long val, int nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -611,7 +626,11 @@
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 getreg (unsigned long regnum, unsigned long *val, int *nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -1298,7 +1317,9 @@
 	mm_segment_t old_fs = get_fs();
 	unsigned long bundle[2];
 	unsigned long opcode;
+#ifndef XEN
 	struct siginfo si;
+#endif
 	const struct exception_table_entry *eh = NULL;
 	union {
 		unsigned long l;
@@ -1317,6 +1338,9 @@
 	 * user-level unaligned accesses.  Otherwise, a clever program could trick this
 	 * handler into reading an arbitrary kernel addresses...
 	 */
+#ifdef XEN
+printk("ia64_handle_unaligned: called, not working yet\n");
+#else
 	if (!user_mode(regs))
 		eh = search_exception_tables(regs->cr_iip + ia64_psr(regs)->ri);
 	if (user_mode(regs) || eh) {
@@ -1353,6 +1377,7 @@
 
 	if (__copy_from_user(bundle, (void *) regs->cr_iip, 16))
 		goto failure;
+#endif
 
 	/*
 	 * extract the instruction from the bundle given the slot number
@@ -1493,6 +1518,7 @@
 		/* NOT_REACHED */
 	}
   force_sigbus:
+#ifndef XEN
 	si.si_signo = SIGBUS;
 	si.si_errno = 0;
 	si.si_code = BUS_ADRALN;
@@ -1501,5 +1527,6 @@
 	si.si_isr = 0;
 	si.si_imm = 0;
 	force_sig_info(SIGBUS, &si, current);
+#endif
 	goto done;
 }
