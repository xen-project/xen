#ifndef __XEN_CPU_H__
#define __XEN_CPU_H__

#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/notifier.h>

extern spinlock_t cpu_add_remove_lock;

int register_cpu_notifier(struct notifier_block *nb);
void unregister_cpu_notifier(struct notifier_block *nb);
int cpu_notifier_call_chain(unsigned long val, void *v);
int __cpu_notifier_call_chain(
    unsigned long val, void *v, int nr_to_call, int *nr_calls);

/*
 * Notification actions: note that only CPU_{UP,DOWN}_PREPARE may fail ---
 * all other handlers *must* return NOTIFY_DONE.
 */
#define CPU_UP_PREPARE   0x0002 /* CPU is coming up */
#define CPU_UP_CANCELED  0x0003 /* CPU is no longer coming up */
#define CPU_ONLINE       0x0004 /* CPU is up */
#define CPU_DOWN_PREPARE 0x0005 /* CPU is going down */
#define CPU_DOWN_FAILED  0x0006 /* CPU is no longer going down */
#define CPU_DYING        0x0007 /* CPU is nearly dead (in stop_machine ctxt) */
#define CPU_DEAD         0x0008 /* CPU is dead */

#endif /* __XEN_CPU_H__ */
