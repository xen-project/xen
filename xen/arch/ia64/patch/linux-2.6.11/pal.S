 pal.S |    8 ++++++++
 1 files changed, 8 insertions(+)

Index: linux-2.6.11-xendiffs/arch/ia64/kernel/pal.S
===================================================================
--- linux-2.6.11-xendiffs.orig/arch/ia64/kernel/pal.S	2005-03-02 01:38:33.000000000 -0600
+++ linux-2.6.11-xendiffs/arch/ia64/kernel/pal.S	2005-04-06 22:43:53.817885390 -0500
@@ -166,7 +166,11 @@ GLOBAL_ENTRY(ia64_pal_call_phys_static)
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
@@ -225,7 +229,11 @@ GLOBAL_ENTRY(ia64_pal_call_phys_stacked)
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
