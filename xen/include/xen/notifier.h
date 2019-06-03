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

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/kernel.h>
#include <xen/list.h>

/*
 * Xen includes only one type of notifier chains inherited from Linux:
 *     Raw notifier chains: There are no restrictions on callbacks,
 *        registration, or unregistration.  All locking and protection
 *        must be provided by the caller.
 */

struct notifier_block {
    int (*notifier_call)(struct notifier_block *, unsigned long, void *);
    struct list_head chain;
    int priority;
};

struct notifier_head {
    struct list_head head;
};

#define NOTIFIER_HEAD(name) \
    struct notifier_head name = { .head = LIST_HEAD_INIT(name.head) }


void notifier_chain_register(
    struct notifier_head *nh, struct notifier_block *nb);
void notifier_chain_unregister(
    struct notifier_head *nh, struct notifier_block *nb);

int notifier_call_chain(
    struct notifier_head *nh, unsigned long val, void *v,
    struct notifier_block **pcursor);

/* Notifier flag values: OR into @val passed to notifier_call_chain(). */
#define NOTIFY_FORWARD 0x0000 /* Call chain highest-priority-first */
#define NOTIFY_REVERSE 0x8000 /* Call chain lowest-priority-first */

/* Handler completion values */
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
