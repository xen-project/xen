 unaligned.c |   27 +++++++++++++++++++++++++++
 1 files changed, 27 insertions(+)

Index: linux-2.6.11/arch/ia64/kernel/unaligned.c
===================================================================
--- linux-2.6.11.orig/arch/ia64/kernel/unaligned.c	2005-03-02 01:38:25.000000000 -0600
+++ linux-2.6.11/arch/ia64/kernel/unaligned.c	2005-03-19 14:58:51.269335202 -0600
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
 
@@ -437,7 +448,11 @@ get_rse_reg (struct pt_regs *regs, unsig
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 setreg (unsigned long regnum, unsigned long val, int nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -611,7 +626,11 @@ getfpreg (unsigned long regnum, struct i
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 getreg (unsigned long regnum, unsigned long *val, int *nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -1298,7 +1317,9 @@ ia64_handle_unaligned (unsigned long ifa
 	mm_segment_t old_fs = get_fs();
 	unsigned long bundle[2];
 	unsigned long opcode;
+#ifndef XEN
 	struct siginfo si;
+#endif
 	const struct exception_table_entry *eh = NULL;
 	union {
 		unsigned long l;
@@ -1317,6 +1338,9 @@ ia64_handle_unaligned (unsigned long ifa
 	 * user-level unaligned accesses.  Otherwise, a clever program could trick this
 	 * handler into reading an arbitrary kernel addresses...
 	 */
+#ifdef XEN
+printk("ia64_handle_unaligned: called, not working yet\n");
+#else
 	if (!user_mode(regs))
 		eh = search_exception_tables(regs->cr_iip + ia64_psr(regs)->ri);
 	if (user_mode(regs) || eh) {
@@ -1353,6 +1377,7 @@ ia64_handle_unaligned (unsigned long ifa
 
 	if (__copy_from_user(bundle, (void __user *) regs->cr_iip, 16))
 		goto failure;
+#endif
 
 	/*
 	 * extract the instruction from the bundle given the slot number
@@ -1493,6 +1518,7 @@ ia64_handle_unaligned (unsigned long ifa
 		/* NOT_REACHED */
 	}
   force_sigbus:
+#ifndef XEN
 	si.si_signo = SIGBUS;
 	si.si_errno = 0;
 	si.si_code = BUS_ADRALN;
@@ -1501,5 +1527,6 @@ ia64_handle_unaligned (unsigned long ifa
 	si.si_isr = 0;
 	si.si_imm = 0;
 	force_sig_info(SIGBUS, &si, current);
+#endif
 	goto done;
 }
