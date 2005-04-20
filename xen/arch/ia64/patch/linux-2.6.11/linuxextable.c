 extable.c |    2 ++
 1 files changed, 2 insertions(+)

Index: linux-2.6.11-xendiffs/kernel/extable.c
===================================================================
--- linux-2.6.11-xendiffs.orig/kernel/extable.c	2005-03-02 01:37:54.000000000 -0600
+++ linux-2.6.11-xendiffs/kernel/extable.c	2005-04-08 14:30:46.283360881 -0500
@@ -20,6 +20,8 @@
 #include <asm/uaccess.h>
 #include <asm/sections.h>
 
+#define __module_text_address(addr)	(NULL)
+
 extern struct exception_table_entry __start___ex_table[];
 extern struct exception_table_entry __stop___ex_table[];
 
