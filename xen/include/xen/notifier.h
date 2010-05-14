/******************************************************************************
 * include/xen/notifier.h
 *
 * Routines to manage notifier chains for passing status changes to any
 * interested routines.
 *
 * Original code from Linux kernel 2.6.27 (Alan Cox <Alan.Cox@linux.org>)
 */
 
#ifndef __XEN_NOTIFIER_H__
#define __XEN_NOTIFIER_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/errno.h>

/*
 * Xen includes only one type of notifier chains inherited from Linux:
 *     Raw notifier chains: There are no restrictions on callbacks,
 *        registration, or unregistration.  All locking and protection
 *        must be provided by the caller.
 */

struct notifier_block {
    int (*notifier_call)(struct notifier_block *, unsigned long, void *);
    struct notifier_block *next;
    int priority;
};

struct raw_notifier_head {
    struct notifier_block *head;
};

#define RAW_INIT_NOTIFIER_HEAD(name) do {       \
    (name)->head = NULL;                        \
} while (0)

#define RAW_NOTIFIER_INIT(name) { .head = NULL }

#define RAW_NOTIFIER_HEAD(name) \
    struct raw_notifier_head name = RAW_NOTIFIER_INIT(name)

int raw_notifier_chain_register(
    struct raw_notifier_head *nh, struct notifier_block *nb);

int raw_notifier_chain_unregister(
    struct raw_notifier_head *nh, struct notifier_block *nb);

int raw_notifier_call_chain(
    struct raw_notifier_head *nh, unsigned long val, void *v);
int __raw_notifier_call_chain(
    struct raw_notifier_head *nh, unsigned long val, void *v,
    int nr_to_call, int *nr_calls);

#define NOTIFY_DONE  0x0000  /* Don't care */
#define NOTIFY_OK  0x0001  /* Suits me */
#define NOTIFY_STOP_MASK 0x8000  /* Don't call further */
#define NOTIFY_BAD  (NOTIFY_STOP_MASK|0x0002)
/* Bad/Veto action */
/*
 * Clean way to return from the notifier and stop further calls.
 */
#define NOTIFY_STOP  (NOTIFY_OK|NOTIFY_STOP_MASK)

/* Encapsulate (negative) errno value (in particular, NOTIFY_BAD <=> EPERM). */
static inline int notifier_from_errno(int err)
{
    return NOTIFY_STOP_MASK | (NOTIFY_OK - err);
}

/* Restore (negative) errno value from notify return value. */
static inline int notifier_to_errno(int ret)
{
    ret &= ~NOTIFY_STOP_MASK;
    return ret > NOTIFY_OK ? NOTIFY_OK - ret : 0;
}

#define CPU_ONLINE  0x0002 /* CPU (unsigned)v is up */
#define CPU_UP_PREPARE  0x0003 /* CPU (unsigned)v coming up */
#define CPU_UP_CANCELED  0x0004 /* CPU (unsigned)v NOT coming up */
#define CPU_DOWN_PREPARE 0x0005 /* CPU (unsigned)v going down */
#define CPU_DOWN_FAILED  0x0006 /* CPU (unsigned)v NOT going down */
#define CPU_DEAD  0x0007 /* CPU (unsigned)v dead */
#define CPU_DYING  0x0008 /* CPU (unsigned)v not running any task,
                           * not handling interrupts, soon dead */
#define CPU_POST_DEAD  0x0009 /* CPU (unsigned)v dead, cpu_hotplug
                               * lock is dropped */

#endif /* __XEN_NOTIFIER_H__ */
