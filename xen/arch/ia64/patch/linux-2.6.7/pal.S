--- ../../linux-2.6.7/arch/ia64/kernel/pal.S	2004-06-15 23:20:25.000000000 -0600
+++ arch/ia64/pal.S	2005-04-01 12:56:01.000000000 -0700
@@ -163,7 +163,11 @@
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
@@ -218,7 +222,11 @@
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
