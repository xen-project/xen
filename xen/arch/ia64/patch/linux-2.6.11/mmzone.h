 mmzone.h |    4 ++++
 1 files changed, 4 insertions(+)

Index: linux-2.6.11/include/linux/mmzone.h
===================================================================
--- linux-2.6.11.orig/include/linux/mmzone.h	2005-03-02 01:38:10.000000000 -0600
+++ linux-2.6.11/include/linux/mmzone.h	2005-03-19 13:49:30.427573139 -0600
@@ -209,7 +209,11 @@ struct zone {
 	 * rarely used fields:
 	 */
 	char			*name;
+#ifdef XEN
+};
+#else
 } ____cacheline_maxaligned_in_smp;
+#endif
 
 
 /*
