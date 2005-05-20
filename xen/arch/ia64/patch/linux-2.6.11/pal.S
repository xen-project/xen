--- /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/../../linux-2.6.11/arch/ia64/kernel/pal.S	2005-03-01 23:38:33.000000000 -0800
+++ /home/adsharma/disk2/xen-ia64/xeno-unstable-rebase.bk/xen/arch/ia64/pal.S	2005-05-18 12:40:19.000000000 -0700
@@ -166,7 +166,11 @@
 	adds r8  = 1f-1b,r8		// calculate return address for call
 	;;
 	mov loc4=ar.rsc			// save RSE configuration
+#ifdef XEN
+	dep.z loc2=loc2,0,60		// convert pal entry point to physical
+#else // XEN
 	dep.z loc2=loc2,0,61		// convert pal entry point to physical
+#endif // XEN
 	tpa r8=r8			// convert rp to physical
 	;;
 	mov b7 = loc2			// install target to branch reg
@@ -225,7 +229,11 @@
 	mov loc3 = psr		// save psr
 	;;
 	mov loc4=ar.rsc			// save RSE configuration
+#ifdef XEN
+	dep.z loc2=loc2,0,60		// convert pal entry point to physical
+#else // XEN
 	dep.z loc2=loc2,0,61		// convert pal entry point to physical
+#endif // XEN
 	;;
 	mov ar.rsc=0			// put RSE in enforced lazy, LE mode
 	movl r16=PAL_PSR_BITS_TO_CLEAR
