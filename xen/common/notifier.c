/******************************************************************************
 * common/notifier.c
 *
 * Routines to manage notifier chains for passing status changes to any
 * interested routines.
 *
 * Original code from Linux kernel 2.6.27 (Alan Cox <Alan.Cox@linux.org>)
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/notifier.h>

/**
 * notifier_chain_register - Add notifier to a raw notifier chain
 * @nh: Pointer to head of the raw notifier chain
 * @n: New entry in notifier chain
 *
 * Adds a notifier to a raw notifier chain.
 * All locking must be provided by the caller.
 */
void __init notifier_chain_register(
    struct notifier_head *nh, struct notifier_block *n)
{
    struct list_head *chain = &nh->head.chain;
    struct notifier_block *nb;

    while ( chain->next != &nh->head.chain )
    {
        nb = list_entry(chain->next, struct notifier_block, chain);
        if ( n->priority > nb->priority )
            break;
        chain = chain->next;
    }

    list_add(&n->chain, chain);
}

/**
 * notifier_chain_unregister - Remove notifier from a raw notifier chain
 * @nh: Pointer to head of the raw notifier chain
 * @n: Entry to remove from notifier chain
 *
 * Removes a notifier from a raw notifier chain.
 * All locking must be provided by the caller.
 */
void __init notifier_chain_unregister(
    struct notifier_head *nh, struct notifier_block *n)
{
    list_del(&n->chain);
}

/**
 * notifier_call_chain - Informs the registered notifiers about an event.
 * @nh: Pointer to head of the raw notifier chain
 * @val:  Value passed unmodified to notifier function
 * @v:  Pointer passed unmodified to notifier function
 * @pcursor: If non-NULL, position in chain to start from. Also updated on
 *           return to indicate how far notifications got before stopping.
 *
 * Calls each function in a notifier chain in turn.  The functions run in an
 * undefined context. All locking must be provided by the caller.
 *
 * If the return value of the notifier can be and'ed with %NOTIFY_STOP_MASK
 * then notifier_call_chain() will return immediately, with teh return value of
 * the notifier function which halted execution. Otherwise the return value is
 * the return value of the last notifier function called.
 */
int notifier_call_chain(
    struct notifier_head *nh, unsigned long val, void *v,
    struct notifier_block **pcursor)
{
    int ret = NOTIFY_DONE;
    struct list_head *cursor;
    struct notifier_block *nb;
    bool_t reverse = !!(val & NOTIFY_REVERSE);

    cursor = &(pcursor && *pcursor ? *pcursor : &nh->head)->chain;

    do {
        cursor = reverse ? cursor->prev : cursor->next;
        nb = list_entry(cursor, struct notifier_block, chain);
        if ( cursor == &nh->head.chain )
            break;
        ret = nb->notifier_call(nb, val, v);
    } while ( !(ret & NOTIFY_STOP_MASK) );

    if ( pcursor )
        *pcursor = nb;

    return ret;
}
