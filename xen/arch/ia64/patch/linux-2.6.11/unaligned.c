--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/arch/ia64/kernel/unaligned.c	2005-03-01 23:38:25.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/arch/ia64/unaligned.c	2005-05-18 12:40:50.000000000 -0700
@@ -201,7 +201,11 @@
 
 	RPT(r1), RPT(r2), RPT(r3),
 
+#ifdef  CONFIG_VTI
+	RPT(r4), RPT(r5), RPT(r6), RPT(r7),
+#else   //CONFIG_VTI
 	RSW(r4), RSW(r5), RSW(r6), RSW(r7),
+#endif  //CONFIG_VTI
 
 	RPT(r8), RPT(r9), RPT(r10), RPT(r11),
 	RPT(r12), RPT(r13), RPT(r14), RPT(r15),
@@ -291,6 +295,121 @@
 	return reg;
 }
 
+#ifdef CONFIG_VTI
+static void
+set_rse_reg (struct pt_regs *regs, unsigned long r1, unsigned long val, unsigned long nat)
+{
+	struct switch_stack *sw = (struct switch_stack *) regs - 1;
+	unsigned long *bsp, *bspstore, *addr, *rnat_addr, *ubs_end;
+	unsigned long *kbs = (void *) current + IA64_RBS_OFFSET;
+	unsigned long rnats, nat_mask;
+    unsigned long old_rsc,new_rsc;
+	unsigned long on_kbs,rnat;
+	long sof = (regs->cr_ifs) & 0x7f;
+	long sor = 8 * ((regs->cr_ifs >> 14) & 0xf);
+	long rrb_gr = (regs->cr_ifs >> 18) & 0x7f;
+	long ridx = r1 - 32;
+
+	if (ridx >= sof) {
+		/* this should never happen, as the "rsvd register fault" has higher priority */
+		DPRINT("ignoring write to r%lu; only %lu registers are allocated!\n", r1, sof);
+		return;
+	}
+
+	if (ridx < sor)
+		ridx = rotate_reg(sor, rrb_gr, ridx);
+
+    old_rsc=ia64_get_rsc();
+    new_rsc=old_rsc&(~0x3);
+    ia64_set_rsc(new_rsc);
+
+    bspstore = ia64_get_bspstore();
+    bsp =kbs + (regs->loadrs >> 19);//16+3
+
+	addr = ia64_rse_skip_regs(bsp, -sof + ridx);
+    nat_mask = 1UL << ia64_rse_slot_num(addr);
+	rnat_addr = ia64_rse_rnat_addr(addr);
+
+    if(addr >= bspstore){
+
+        ia64_flushrs ();
+        ia64_mf ();
+		*addr = val;
+        bspstore = ia64_get_bspstore();
+    	rnat = ia64_get_rnat ();
+        if(bspstore < rnat_addr){
+            rnat=rnat&(~nat_mask);
+        }else{
+            *rnat_addr = (*rnat_addr)&(~nat_mask);
+        }
+        ia64_mf();
+        ia64_loadrs();
+        ia64_set_rnat(rnat);
+    }else{
+
+    	rnat = ia64_get_rnat ();
+		*addr = val;
+        if(bspstore < rnat_addr){
+            rnat=rnat&(~nat_mask);
+        }else{
+            *rnat_addr = (*rnat_addr)&(~nat_mask);
+        }
+        ia64_set_bspstore (bspstore);
+        ia64_set_rnat(rnat);
+    }
+    ia64_set_rsc(old_rsc);
+}
+
+
+static void
+get_rse_reg (struct pt_regs *regs, unsigned long r1, unsigned long *val, unsigned long *nat)
+{
+	struct switch_stack *sw = (struct switch_stack *) regs - 1;
+	unsigned long *bsp, *addr, *rnat_addr, *ubs_end, *bspstore;
+	unsigned long *kbs = (void *) current + IA64_RBS_OFFSET;
+	unsigned long rnats, nat_mask;
+	unsigned long on_kbs;
+    unsigned long old_rsc, new_rsc;
+	long sof = (regs->cr_ifs) & 0x7f;
+	long sor = 8 * ((regs->cr_ifs >> 14) & 0xf);
+	long rrb_gr = (regs->cr_ifs >> 18) & 0x7f;
+	long ridx = r1 - 32;
+
+	if (ridx >= sof) {
+		/* read of out-of-frame register returns an undefined value; 0 in our case.  */
+		DPRINT("ignoring read from r%lu; only %lu registers are allocated!\n", r1, sof);
+		panic("wrong stack register number");
+	}
+
+	if (ridx < sor)
+		ridx = rotate_reg(sor, rrb_gr, ridx);
+
+    old_rsc=ia64_get_rsc();
+    new_rsc=old_rsc&(~(0x3));
+    ia64_set_rsc(new_rsc);
+
+    bspstore = ia64_get_bspstore();
+    bsp =kbs + (regs->loadrs >> 19); //16+3;
+
+	addr = ia64_rse_skip_regs(bsp, -sof + ridx);
+    nat_mask = 1UL << ia64_rse_slot_num(addr);
+	rnat_addr = ia64_rse_rnat_addr(addr);
+
+    if(addr >= bspstore){
+
+        ia64_flushrs ();
+        ia64_mf ();
+        bspstore = ia64_get_bspstore();
+    }
+	*val=*addr;
+    if(bspstore < rnat_addr){
+        *nat=!!(ia64_get_rnat()&nat_mask);
+    }else{
+        *nat = !!((*rnat_addr)&nat_mask);
+    }
+    ia64_set_rsc(old_rsc);
+}
+#else // CONFIG_VTI
 static void
 set_rse_reg (struct pt_regs *regs, unsigned long r1, unsigned long val, int nat)
 {
@@ -435,9 +554,14 @@
 		*nat = 0;
 	return;
 }
+#endif // CONFIG_VTI
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 setreg (unsigned long regnum, unsigned long val, int nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -466,7 +590,11 @@
 		unat = &sw->ar_unat;
 	} else {
 		addr = (unsigned long)regs;
+#ifdef CONFIG_VTI
+		unat = &regs->eml_unat;
+#else //CONFIG_VTI
 		unat = &sw->caller_unat;
+#endif  //CONFIG_VTI
 	}
 	DPRINT("tmp_base=%lx switch_stack=%s offset=%d\n",
 	       addr, unat==&sw->ar_unat ? "yes":"no", GR_OFFS(regnum));
@@ -522,7 +650,11 @@
 	 */
 	if (regnum >= IA64_FIRST_ROTATING_FR) {
 		ia64_sync_fph(current);
+#ifdef XEN
+		current->arch._thread.fph[fph_index(regs, regnum)] = *fpval;
+#else
 		current->thread.fph[fph_index(regs, regnum)] = *fpval;
+#endif
 	} else {
 		/*
 		 * pt_regs or switch_stack ?
@@ -581,7 +713,11 @@
 	 */
 	if (regnum >= IA64_FIRST_ROTATING_FR) {
 		ia64_flush_fph(current);
+#ifdef XEN
+		*fpval = current->arch._thread.fph[fph_index(regs, regnum)];
+#else
 		*fpval = current->thread.fph[fph_index(regs, regnum)];
+#endif
 	} else {
 		/*
 		 * f0 = 0.0, f1= 1.0. Those registers are constant and are thus
@@ -611,7 +747,11 @@
 }
 
 
+#ifdef XEN
+void
+#else
 static void
+#endif
 getreg (unsigned long regnum, unsigned long *val, int *nat, struct pt_regs *regs)
 {
 	struct switch_stack *sw = (struct switch_stack *) regs - 1;
@@ -640,7 +780,11 @@
 		unat = &sw->ar_unat;
 	} else {
 		addr = (unsigned long)regs;
+#ifdef  CONFIG_VTI
+		unat = &regs->eml_unat;;
+#else   //CONFIG_VTI
 		unat = &sw->caller_unat;
+#endif  //CONFIG_VTI
 	}
 
 	DPRINT("addr_base=%lx offset=0x%x\n", addr,  GR_OFFS(regnum));
@@ -1294,6 +1438,9 @@
 void
 ia64_handle_unaligned (unsigned long ifa, struct pt_regs *regs)
 {
+#ifdef XEN
+printk("ia64_handle_unaligned: called, not working yet\n");
+#else
 	struct ia64_psr *ipsr = ia64_psr(regs);
 	mm_segment_t old_fs = get_fs();
 	unsigned long bundle[2];
@@ -1502,4 +1649,5 @@
 	si.si_imm = 0;
 	force_sig_info(SIGBUS, &si, current);
 	goto done;
+#endif
 }
