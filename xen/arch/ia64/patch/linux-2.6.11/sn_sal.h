--- /data/lwork/attica1/edwardsg/linux-2.6.11/include/asm-ia64/sn/sn_sal.h	2005-03-02 01:38:33 -06:00
+++ include/asm-ia64/sn/sn_sal.h	2005-06-01 14:31:47 -05:00
@@ -123,6 +123,7 @@
 #define SALRET_ERROR		(-3)


+#ifndef XEN
 /**
  * sn_sal_rev_major - get the major SGI SAL revision number
  *
@@ -226,6 +227,7 @@ ia64_sn_get_klconfig_addr(nasid_t nasid)
 	}
 	return ret_stuff.v0 ? __va(ret_stuff.v0) : NULL;
 }
+#endif /* !XEN */

 /*
  * Returns the next console character.
@@ -304,6 +306,7 @@ ia64_sn_console_putb(const char *buf, in
 	return (u64)0;
 }

+#ifndef XEN
 /*
  * Print a platform error record
  */
@@ -987,5 +990,5 @@ ia64_sn_hwperf_op(nasid_t nasid, u64 opc
 		*v0 = (int) rv.v0;
 	return (int) rv.status;
 }
-
+#endif /* !XEN */
 #endif /* _ASM_IA64_SN_SN_SAL_H */
