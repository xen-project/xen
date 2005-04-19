 cpumask.h |    2 +-
 1 files changed, 1 insertion(+), 1 deletion(-)

Index: linux-2.6.11-xendiffs/include/linux/cpumask.h
===================================================================
--- linux-2.6.11-xendiffs.orig/include/linux/cpumask.h	2005-03-02 01:38:00.000000000 -0600
+++ linux-2.6.11-xendiffs/include/linux/cpumask.h	2005-03-24 15:06:18.408145243 -0600
@@ -341,11 +341,11 @@ static inline int __cpumask_parse(const 
  *        main(){ set1(3); set2(5); }
  */
 
+#if NR_CPUS > 1
 extern cpumask_t cpu_possible_map;
 extern cpumask_t cpu_online_map;
 extern cpumask_t cpu_present_map;
 
-#if NR_CPUS > 1
 #define num_online_cpus()	cpus_weight(cpu_online_map)
 #define num_possible_cpus()	cpus_weight(cpu_possible_map)
 #define num_present_cpus()	cpus_weight(cpu_present_map)
