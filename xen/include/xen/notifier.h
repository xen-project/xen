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

#define NOTIFY_DONE      0x0000
#define NOTIFY_STOP_MASK 0x8000
#define NOTIFY_STOP      (NOTIFY_STOP_MASK|NOTIFY_DONE)
#define NOTIFY_BAD       (NOTIFY_STOP_MASK|EINVAL)

/* Encapsulate (negative) errno value. */
static inline int notifier_from_errno(int err)
{
    return NOTIFY_STOP_MASK | -err;
}

/* Restore (negative) errno value from notify return value. */
static inline int notifier_to_errno(int ret)
{
    return -(ret & ~NOTIFY_STOP_MASK);
}

#endif /* __XEN_NOTIFIER_H__ */
