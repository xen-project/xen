--- /home/djm/src/xen/xeno-ia64.bk/xen/linux-2.6.7/mm/slab.c	2004-06-15 23:19:44.000000000 -0600
+++ /home/djm/src/xen/xeno-ia64.bk/xen/arch/ia64/slab.c	2004-12-17 13:47:03.000000000 -0700
@@ -86,15 +86,30 @@
 #include	<linux/init.h>
 #include	<linux/compiler.h>
 #include	<linux/seq_file.h>
+#ifndef XEN
 #include	<linux/notifier.h>
 #include	<linux/kallsyms.h>
 #include	<linux/cpu.h>
 #include	<linux/sysctl.h>
 #include	<linux/module.h>
+#endif
 
 #include	<asm/uaccess.h>
 #include	<asm/cacheflush.h>
+#ifndef XEN
 #include	<asm/tlbflush.h>
+#endif
+
+#ifdef XEN
+#define lock_cpu_hotplug()	do { } while (0)
+#define unlock_cpu_hotplug()	do { } while (0)
+#define might_sleep_if(x)	do { } while (0)
+#define	dump_stack()		do { } while (0)
+#define start_cpu_timer(cpu)	do { } while (0)
+static inline void __down(struct semaphore *sem) { }
+static inline void __up(struct semaphore *sem) { }
+static inline void might_sleep(void) { }
+#endif
 
 /*
  * DEBUG	- 1 for kmem_cache_create() to honour; SLAB_DEBUG_INITIAL,
@@ -530,7 +545,9 @@
 	FULL
 } g_cpucache_up;
 
+#ifndef XEN
 static DEFINE_PER_CPU(struct timer_list, reap_timers);
+#endif
 
 static void reap_timer_fnc(unsigned long data);
 static void free_block(kmem_cache_t* cachep, void** objpp, int len);
@@ -588,6 +605,7 @@
  * Add the CPU number into the expiry time to minimize the possibility of the
  * CPUs getting into lockstep and contending for the global cache chain lock.
  */
+#ifndef XEN
 static void __devinit start_cpu_timer(int cpu)
 {
 	struct timer_list *rt = &per_cpu(reap_timers, cpu);
@@ -600,6 +618,7 @@
 		add_timer_on(rt, cpu);
 	}
 }
+#endif
 
 #ifdef CONFIG_HOTPLUG_CPU
 static void stop_cpu_timer(int cpu)
@@ -634,6 +653,7 @@
 	return nc;
 }
 
+#ifndef XEN
 static int __devinit cpuup_callback(struct notifier_block *nfb,
 				  unsigned long action,
 				  void *hcpu)
@@ -693,6 +713,7 @@
 }
 
 static struct notifier_block cpucache_notifier = { &cpuup_callback, NULL, 0 };
+#endif
 
 /* Initialisation.
  * Called after the gfp() functions have been enabled, and before smp_init().
@@ -805,10 +826,14 @@
 	/* Done! */
 	g_cpucache_up = FULL;
 
+#ifdef XEN
+printk("kmem_cache_init: some parts commented out, ignored\n");
+#else
 	/* Register a cpu startup notifier callback
 	 * that initializes ac_data for all new cpus
 	 */
 	register_cpu_notifier(&cpucache_notifier);
+#endif
 	
 
 	/* The reap timers are started later, with a module init call:
@@ -886,8 +911,10 @@
 		page++;
 	}
 	sub_page_state(nr_slab, nr_freed);
+#ifndef XEN
 	if (current->reclaim_state)
 		current->reclaim_state->reclaimed_slab += nr_freed;
+#endif
 	free_pages((unsigned long)addr, cachep->gfporder);
 	if (cachep->flags & SLAB_RECLAIM_ACCOUNT) 
 		atomic_sub(1<<cachep->gfporder, &slab_reclaim_pages);
@@ -1363,8 +1390,10 @@
 					+ cachep->num;
 	} 
 
+#ifndef XEN
 	cachep->lists.next_reap = jiffies + REAPTIMEOUT_LIST3 +
 					((unsigned long)cachep)%REAPTIMEOUT_LIST3;
+#endif
 
 	/* Need the semaphore to access the chain. */
 	down(&cache_chain_sem);
@@ -2237,8 +2266,10 @@
 
 	if (unlikely(addr < min_addr))
 		goto out;
+#ifndef XEN
 	if (unlikely(addr > (unsigned long)high_memory - size))
 		goto out;
+#endif
 	if (unlikely(addr & align_mask))
 		goto out;
 	if (unlikely(!kern_addr_valid(addr)))
@@ -2769,6 +2800,7 @@
  */
 static void reap_timer_fnc(unsigned long cpu)
 {
+#ifndef XEN
 	struct timer_list *rt = &__get_cpu_var(reap_timers);
 
 	/* CPU hotplug can drag us off cpu: don't run on wrong CPU */
@@ -2776,6 +2808,7 @@
 		cache_reap();
 		mod_timer(rt, jiffies + REAPTIMEOUT_CPUC + cpu);
 	}
+#endif
 }
 
 #ifdef CONFIG_PROC_FS
