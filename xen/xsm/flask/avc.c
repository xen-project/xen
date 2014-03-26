/*
 * Implementation of the kernel access vector cache (AVC).
 *
 * Authors:  Stephen Smalley, <sds@epoch.ncsc.mil>
 *           James Morris <jmorris@redhat.com>
 *
 * Update:   KaiGai, Kohei <kaigai@ak.jp.nec.com>
 *     Replaced the avc_lock spinlock by RCU.
 *
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */
 
/* Ported to Xen 3.0, George Coker, <gscoker@alpha.ncsc.mil> */
 
#include <xen/lib.h>
#include <xen/xmalloc.h>
#include <xen/types.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/prefetch.h>
#include <xen/kernel.h>
#include <xen/sched.h>
#include <xen/init.h>
#include <xen/rcupdate.h>
#include <asm/atomic.h>
#include <asm/current.h>
#include <public/xsm/flask_op.h>

#include "avc.h"
#include "avc_ss.h"

static const struct av_perm_to_string av_perm_to_string[] = {
#define S_(c, v, s) { c, v, s },
#include "av_perm_to_string.h"
#undef S_
};

static const char *class_to_string[] = {
#define S_(s) s,
#include "class_to_string.h"
#undef S_
};

const struct selinux_class_perm selinux_class_perm = {
    .av_perm_to_string = av_perm_to_string,
    .av_pts_len = ARRAY_SIZE(av_perm_to_string),
    .class_to_string = class_to_string,
    .cts_len = ARRAY_SIZE(class_to_string),
};

#define AVC_CACHE_SLOTS            512
#define AVC_DEF_CACHE_THRESHOLD        512
#define AVC_CACHE_RECLAIM        16

#ifdef FLASK_AVC_STATS
#define avc_cache_stats_incr(field)                 \
do {                                \
    __get_cpu_var(avc_cache_stats).field++;        \
} while (0)
#else
#define avc_cache_stats_incr(field)    do {} while (0)
#endif

struct avc_entry {
    u32            ssid;
    u32            tsid;
    u16            tclass;
    struct av_decision    avd;
};

struct avc_node {
    struct avc_entry    ae;
    struct hlist_node   list; /* anchored in avc_cache->slots[i] */
    struct rcu_head     rhead;
};

struct avc_cache {
    struct hlist_head    slots[AVC_CACHE_SLOTS]; /* head for avc_node->list */
    spinlock_t        slots_lock[AVC_CACHE_SLOTS]; /* lock for writes */
    atomic_t        lru_hint;    /* LRU hint for reclaim scan */
    atomic_t        active_nodes;
    u32            latest_notif;    /* latest revocation notification */
};

struct avc_callback_node {
    int (*callback) (u32 event, u32 ssid, u32 tsid,
                     u16 tclass, u32 perms,
                     u32 *out_retained);
    u32 events;
    u32 ssid;
    u32 tsid;
    u16 tclass;
    u32 perms;
    struct avc_callback_node *next;
};

/* Exported via Flask hypercall */
unsigned int avc_cache_threshold = AVC_DEF_CACHE_THRESHOLD;

#ifdef FLASK_AVC_STATS
DEFINE_PER_CPU(struct avc_cache_stats, avc_cache_stats);
#endif

static struct avc_cache avc_cache;
static struct avc_callback_node *avc_callbacks;

static DEFINE_RCU_READ_LOCK(avc_rcu_lock);

static inline int avc_hash(u32 ssid, u32 tsid, u16 tclass)
{
    return (ssid ^ (tsid<<2) ^ (tclass<<4)) & (AVC_CACHE_SLOTS - 1);
}

/* no use making this larger than the printk buffer */
#define AVC_BUF_SIZE 1024
static DEFINE_SPINLOCK(avc_emerg_lock);
static char avc_emerg_buf[AVC_BUF_SIZE];

struct avc_dump_buf {
    char *start;
    char *pos;
    u32 free;
};

static void avc_printk(struct avc_dump_buf *buf, const char *fmt, ...)
{
    int i;
    va_list args;

 again:
    va_start(args, fmt);
    i = vsnprintf(buf->pos, buf->free, fmt, args);
    va_end(args);
    if ( i < buf->free )
    {
        buf->pos += i;
        buf->free -= i;
    }
    else if ( buf->free < AVC_BUF_SIZE )
    {
        buf->pos[0] = 0;
        printk("%s", buf->start);
        buf->pos = buf->start;
        buf->free = AVC_BUF_SIZE;
        goto again;
    }
    else
    {
        printk("%s", buf->start);
        printk("\navc_printk: overflow\n");
        buf->pos = buf->start;
        buf->free = AVC_BUF_SIZE;
    }
}

/**
 * avc_dump_av - Display an access vector in human-readable form.
 * @tclass: target security class
 * @av: access vector
 */
static void avc_dump_av(struct avc_dump_buf *buf, u16 tclass, u32 av)
{
    int i, i2, perm;

    if ( av == 0 )
    {
        avc_printk(buf, " null");
        return;
    }

    avc_printk(buf, " {");
    i = 0;
    perm = 1;

    while ( i < sizeof(av) * 8 )
    {
        if ( perm & av )
        {
            for ( i2 = 0; i2 < ARRAY_SIZE(av_perm_to_string); i2++ )
            {
                if ( (av_perm_to_string[i2].tclass == tclass) &&
                     (av_perm_to_string[i2].value == perm) )
                    break;
            }
            if ( i2 < ARRAY_SIZE(av_perm_to_string) )
            {
                avc_printk(buf, " %s", av_perm_to_string[i2].name);
                av &= ~perm;
            }
        }
        i++;
        perm <<= 1;
    }

    if ( av )
        avc_printk(buf, " %#x", av);

    avc_printk(buf, " }");
}

/**
 * avc_dump_query - Display a SID pair and a class in human-readable form.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 */
static void avc_dump_query(struct avc_dump_buf *buf, u32 ssid, u32 tsid, u16 tclass)
{
    int rc;
    char *scontext;
    u32 scontext_len;

    rc = security_sid_to_context(ssid, &scontext, &scontext_len);
    if ( rc )
        avc_printk(buf, "ssid=%d", ssid);
    else
    {
        avc_printk(buf, "scontext=%s", scontext);
        xfree(scontext);
    }

    rc = security_sid_to_context(tsid, &scontext, &scontext_len);
    if ( rc )
        avc_printk(buf, " tsid=%d", tsid);
    else
    {
        avc_printk(buf, " tcontext=%s", scontext);
        xfree(scontext);
    }

    avc_printk(buf, " tclass=%s", class_to_string[tclass]);
}

/**
 * avc_init - Initialize the AVC.
 *
 * Initialize the access vector cache.
 */
void __init avc_init(void)
{
    int i;

    for ( i = 0; i < AVC_CACHE_SLOTS; i++ )
    {
        INIT_HLIST_HEAD(&avc_cache.slots[i]);
        spin_lock_init(&avc_cache.slots_lock[i]);
    }
    atomic_set(&avc_cache.active_nodes, 0);
    atomic_set(&avc_cache.lru_hint, 0);

    printk("AVC INITIALIZED\n");
}

int avc_get_hash_stats(struct xen_flask_hash_stats *arg)
{
    int i, chain_len, max_chain_len, slots_used;
    struct avc_node *node;
    struct hlist_head *head;

    rcu_read_lock(&avc_rcu_lock);

    slots_used = 0;
    max_chain_len = 0;
    for ( i = 0; i < AVC_CACHE_SLOTS; i++ )
    {
        head = &avc_cache.slots[i];
        if ( !hlist_empty(head) )
        {
            struct hlist_node *next;

            slots_used++;
            chain_len = 0;
            hlist_for_each_entry_rcu(node, next, head, list)
                chain_len++;
            if ( chain_len > max_chain_len )
                max_chain_len = chain_len;
        }
    }

    rcu_read_unlock(&avc_rcu_lock);
    
    arg->entries = atomic_read(&avc_cache.active_nodes);
    arg->buckets_used = slots_used;
    arg->buckets_total = AVC_CACHE_SLOTS;
    arg->max_chain_len = max_chain_len;

    return 0;
}

static void avc_node_free(struct rcu_head *rhead)
{
    struct avc_node *node = container_of(rhead, struct avc_node, rhead);
    xfree(node);
    avc_cache_stats_incr(frees);
}

static void avc_node_delete(struct avc_node *node)
{
    hlist_del_rcu(&node->list);
    call_rcu(&node->rhead, avc_node_free);
    atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_kill(struct avc_node *node)
{
    xfree(node);
    avc_cache_stats_incr(frees);
    atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_replace(struct avc_node *new, struct avc_node *old)
{
    hlist_replace_rcu(&old->list, &new->list);
    call_rcu(&old->rhead, avc_node_free);
    atomic_dec(&avc_cache.active_nodes);
}

static inline int avc_reclaim_node(void)
{
    struct avc_node *node;
    int hvalue, try, ecx;
    unsigned long flags;
    struct hlist_head *head;
    struct hlist_node *next;
    spinlock_t *lock;

    for ( try = 0, ecx = 0; try < AVC_CACHE_SLOTS; try++ )
    {
        atomic_inc(&avc_cache.lru_hint);
        hvalue =  atomic_read(&avc_cache.lru_hint) & (AVC_CACHE_SLOTS - 1);
        head = &avc_cache.slots[hvalue];
        lock = &avc_cache.slots_lock[hvalue];

        spin_lock_irqsave(&avc_cache.slots_lock[hvalue], flags);
        rcu_read_lock(&avc_rcu_lock);
        hlist_for_each_entry(node, next, head, list)
        {
            avc_node_delete(node);
            avc_cache_stats_incr(reclaims);
            ecx++;
            if ( ecx >= AVC_CACHE_RECLAIM )
            {
                rcu_read_unlock(&avc_rcu_lock);
                spin_unlock_irqrestore(lock, flags);
                goto out;
            }
        }
        rcu_read_unlock(&avc_rcu_lock);
        spin_unlock_irqrestore(lock, flags);
    }    
 out:
    return ecx;
}

static struct avc_node *avc_alloc_node(void)
{
    struct avc_node *node;

    node = xzalloc(struct avc_node);
    if (!node)
        goto out;

    INIT_RCU_HEAD(&node->rhead);
    INIT_HLIST_NODE(&node->list);
    avc_cache_stats_incr(allocations);

    atomic_inc(&avc_cache.active_nodes);
    if ( atomic_read(&avc_cache.active_nodes) > avc_cache_threshold )
        avc_reclaim_node();

 out:
    return node;
}

static void avc_node_populate(struct avc_node *node, u32 ssid, u32 tsid,
                              u16 tclass, struct av_decision *avd)
{
    node->ae.ssid = ssid;
    node->ae.tsid = tsid;
    node->ae.tclass = tclass;
    memcpy(&node->ae.avd, avd, sizeof(node->ae.avd));
}

static inline struct avc_node *avc_search_node(u32 ssid, u32 tsid, u16 tclass)
{
    struct avc_node *node, *ret = NULL;
    int hvalue;
    struct hlist_head *head;
    struct hlist_node *next;

    hvalue = avc_hash(ssid, tsid, tclass);
    head = &avc_cache.slots[hvalue];
    hlist_for_each_entry_rcu(node, next, head, list)
    {
        if ( ssid == node->ae.ssid &&
             tclass == node->ae.tclass &&
             tsid == node->ae.tsid )
        {
            ret = node;
            break;
        }
    }

    return ret;
}

/**
 * avc_lookup - Look up an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 *
 * Look up an AVC entry that is valid for the
 * @requested permissions between the SID pair
 * (@ssid, @tsid), interpreting the permissions
 * based on @tclass.  If a valid AVC entry exists,
 * then this function return the avc_node.
 * Otherwise, this function returns NULL.
 */
static struct avc_node *avc_lookup(u32 ssid, u32 tsid, u16 tclass)
{
    struct avc_node *node;

    avc_cache_stats_incr(lookups);
    node = avc_search_node(ssid, tsid, tclass);

    if ( node )
        avc_cache_stats_incr(hits);
    else
        avc_cache_stats_incr(misses);

    return node;
}

static int avc_latest_notif_update(int seqno, int is_insert)
{
    int ret = 0;
    static DEFINE_SPINLOCK(notif_lock);
    unsigned long flag;

    spin_lock_irqsave(&notif_lock, flag);
    if ( is_insert )
    {
        if ( seqno < avc_cache.latest_notif )
        {
            printk(KERN_WARNING "avc:  seqno %d < latest_notif %d\n",
                   seqno, avc_cache.latest_notif);
            ret = -EAGAIN;
        }
    }
    else
    {
        if ( seqno > avc_cache.latest_notif )
            avc_cache.latest_notif = seqno;
    }
    spin_unlock_irqrestore(&notif_lock, flag);

    return ret;
}

/**
 * avc_insert - Insert an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @ae: AVC entry
 *
 * Insert an AVC entry for the SID pair
 * (@ssid, @tsid) and class @tclass.
 * The access vectors and the sequence number are
 * normally provided by the security server in
 * response to a security_compute_av() call.  If the
 * sequence number @ae->avd.seqno is not less than the latest
 * revocation notification, then the function copies
 * the access vectors into a cache entry, returns
 * avc_node inserted. Otherwise, this function returns NULL.
 */
static struct avc_node *avc_insert(u32 ssid, u32 tsid, u16 tclass,
                                   struct av_decision *avd)
{
    struct avc_node *pos, *node = NULL;
    int hvalue;
    unsigned long flag;

    if ( avc_latest_notif_update(avd->seqno, 1) )
        goto out;

    node = avc_alloc_node();
    if ( node )
    {
        struct hlist_head *head;
        struct hlist_node *next;
        spinlock_t *lock;

        hvalue = avc_hash(ssid, tsid, tclass);
        avc_node_populate(node, ssid, tsid, tclass, avd);

        head = &avc_cache.slots[hvalue];
        lock = &avc_cache.slots_lock[hvalue];

        spin_lock_irqsave(lock, flag);
        hlist_for_each_entry(pos, next, head, list)
        {
            if ( pos->ae.ssid == ssid &&
                 pos->ae.tsid == tsid &&
                 pos->ae.tclass == tclass )
            {
                avc_node_replace(node, pos);
                goto found;
            }
        }
        hlist_add_head_rcu(&node->list, head);
    found:
        spin_unlock_irqrestore(lock, flag);
    }
 out:
    return node;
}

/**
 * avc_audit - Audit the granting or denial of permissions.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions
 * @avd: access vector decisions
 * @result: result from avc_has_perm_noaudit
 * @a:  auxiliary audit data
 *
 * Audit the granting or denial of permissions in accordance
 * with the policy.  This function is typically called by
 * avc_has_perm() after a permission check, but can also be
 * called directly by callers who use avc_has_perm_noaudit()
 * in order to separate the permission check from the auditing.
 * For example, this separation is useful when the permission check must
 * be performed under a lock, to allow the lock to be released
 * before calling the auditing code.
 */
void avc_audit(u32 ssid, u32 tsid, u16 tclass, u32 requested,
               struct av_decision *avd, int result, struct avc_audit_data *a)
{
    struct domain *cdom = current->domain;
    u32 denied, audited;
    struct avc_dump_buf buf;

    denied = requested & ~avd->allowed;
    if ( denied )
    {
        audited = denied;
        if ( !(audited & avd->auditdeny) )
            return;
    }
    else if ( result )
    {
        audited = denied = requested;
    }
    else
    {
        audited = requested;
        if ( !(audited & avd->auditallow) )
            return;
    }
    buf.start = xmalloc_bytes(AVC_BUF_SIZE);
    if ( !buf.start )
    {
        spin_lock(&avc_emerg_lock);
        buf.start = avc_emerg_buf;
    }
    buf.pos = buf.start;
    buf.free = AVC_BUF_SIZE;

    avc_printk(&buf, "avc:  %s ", denied ? "denied" : "granted");
    avc_dump_av(&buf, tclass, audited);
    avc_printk(&buf, " for ");

    if ( a && (a->sdom || a->tdom) )
    {
        if ( a->sdom && a->tdom && a->sdom != a->tdom )
            avc_printk(&buf, "domid=%d target=%d ", a->sdom->domain_id, a->tdom->domain_id);
        else if ( a->sdom )
            avc_printk(&buf, "domid=%d ", a->sdom->domain_id);
        else
            avc_printk(&buf, "target=%d ", a->tdom->domain_id);
    }
    else if ( cdom )
        avc_printk(&buf, "domid=%d ", cdom->domain_id);
    switch ( a ? a->type : 0 ) {
    case AVC_AUDIT_DATA_DEV:
        avc_printk(&buf, "device=%#lx ", a->device);
        break;
    case AVC_AUDIT_DATA_IRQ:
        avc_printk(&buf, "irq=%d ", a->irq);
        break;
    case AVC_AUDIT_DATA_RANGE:
        avc_printk(&buf, "range=%#lx-%#lx ", a->range.start, a->range.end);
        break;
    case AVC_AUDIT_DATA_MEMORY:
        avc_printk(&buf, "pte=%#lx mfn=%#lx ", a->memory.pte, a->memory.mfn);
        break;
    }

    avc_dump_query(&buf, ssid, tsid, tclass);
    avc_printk(&buf, "\n");
    printk("%s", buf.start);

    if ( buf.start == avc_emerg_buf )
        spin_unlock(&avc_emerg_lock);
    else
        xfree(buf.start);
}

/**
 * avc_add_callback - Register a callback for security events.
 * @callback: callback function
 * @events: security events
 * @ssid: source security identifier or %SECSID_WILD
 * @tsid: target security identifier or %SECSID_WILD
 * @tclass: target security class
 * @perms: permissions
 *
 * Register a callback function for events in the set @events
 * related to the SID pair (@ssid, @tsid) and
 * and the permissions @perms, interpreting
 * @perms based on @tclass.  Returns %0 on success or
 * -%ENOMEM if insufficient memory exists to add the callback.
 */
int avc_add_callback(int (*callback)(u32 event, u32 ssid, u32 tsid, u16 tclass,
                                     u32 perms, u32 *out_retained), u32 events, u32 ssid, u32 tsid,
                     u16 tclass, u32 perms)
{
    struct avc_callback_node *c;
    int rc = 0;

    c = xmalloc(struct avc_callback_node);
    if ( !c )
    {
        rc = -ENOMEM;
        goto out;
    }

    c->callback = callback;
    c->events = events;
    c->ssid = ssid;
    c->tsid = tsid;
    c->perms = perms;
    c->next = avc_callbacks;
    avc_callbacks = c;
 out:
    return rc;
}

/**
 * avc_update_node Update an AVC entry
 * @event : Updating event
 * @perms : Permission mask bits
 * @ssid,@tsid,@tclass : identifier of an AVC entry
 *
 * if a valid AVC entry doesn't exist,this function returns -ENOENT.
 * if kmalloc() called internal returns NULL, this function returns -ENOMEM.
 * otherwise, this function update the AVC entry. The original AVC-entry object
 * will release later by RCU.
 */
static int avc_update_node(u32 event, u32 perms, u32 ssid, u32 tsid, u16 tclass,
                           u32 seqno)
{
    int hvalue, rc = 0;
    unsigned long flag;
    struct avc_node *pos, *node, *orig = NULL;
    struct hlist_head *head;
    struct hlist_node *next;
    spinlock_t *lock;
    
    node = avc_alloc_node();
    if ( !node )
    {
        rc = -ENOMEM;
        goto out;
    }

    hvalue = avc_hash(ssid, tsid, tclass);    

    head = &avc_cache.slots[hvalue];
    lock = &avc_cache.slots_lock[hvalue];

    spin_lock_irqsave(lock, flag);

    hlist_for_each_entry(pos, next, head, list)
    {
        if ( ssid == pos->ae.ssid &&
             tsid == pos->ae.tsid &&
             tclass == pos->ae.tclass &&
             seqno == pos->ae.avd.seqno )
        {
            orig = pos;
            break;
        }
    }

    if ( !orig )
    {
        rc = -ENOENT;
        avc_node_kill(node);
        goto out_unlock;
    }

    /*
     * Copy and replace original node.
     */

    avc_node_populate(node, ssid, tsid, tclass, &orig->ae.avd);

    switch ( event )
    {
    case AVC_CALLBACK_GRANT:
        node->ae.avd.allowed |= perms;
        break;
    case AVC_CALLBACK_TRY_REVOKE:
    case AVC_CALLBACK_REVOKE:
        node->ae.avd.allowed &= ~perms;
        break;
    case AVC_CALLBACK_AUDITALLOW_ENABLE:
        node->ae.avd.auditallow |= perms;
        break;
    case AVC_CALLBACK_AUDITALLOW_DISABLE:
        node->ae.avd.auditallow &= ~perms;
        break;
    case AVC_CALLBACK_AUDITDENY_ENABLE:
        node->ae.avd.auditdeny |= perms;
        break;
    case AVC_CALLBACK_AUDITDENY_DISABLE:
        node->ae.avd.auditdeny &= ~perms;
        break;
    }
    avc_node_replace(node, orig);
 out_unlock:
    spin_unlock_irqrestore(lock, flag);
 out:
    return rc;
}

/**
 * avc_ss_reset - Flush the cache and revalidate migrated permissions.
 * @seqno: policy sequence number
 */
int avc_ss_reset(u32 seqno)
{
    struct avc_callback_node *c;
    int i, rc = 0, tmprc;
    unsigned long flag;
    struct avc_node *node;
    struct hlist_head *head;
    struct hlist_node *next;
    spinlock_t *lock;

    for ( i = 0; i < AVC_CACHE_SLOTS; i++ )
    {
        head = &avc_cache.slots[i];
        lock = &avc_cache.slots_lock[i];

        spin_lock_irqsave(lock, flag);
        rcu_read_lock(&avc_rcu_lock);
        hlist_for_each_entry(node, next, head, list)
            avc_node_delete(node);
        rcu_read_unlock(&avc_rcu_lock);
        spin_unlock_irqrestore(lock, flag);
    }
    
    for ( c = avc_callbacks; c; c = c->next )
    {
        if ( c->events & AVC_CALLBACK_RESET )
        {
            tmprc = c->callback(AVC_CALLBACK_RESET,
                                0, 0, 0, 0, NULL);
            /* save the first error encountered for the return
               value and continue processing the callbacks */
            if ( !rc )
                rc = tmprc;
        }
    }

    avc_latest_notif_update(seqno, 0);
    return rc;
}

/**
 * avc_has_perm_noaudit - Check permissions but perform no auditing.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @avd: access vector decisions
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Return a copy of the decisions
 * in @avd.  Return %0 if all @requested permissions are granted,
 * -%EACCES if any permissions are denied, or another -errno upon
 * other errors.  This function is typically called by avc_has_perm(),
 * but may also be called directly to separate permission checking from
 * auditing, e.g. in cases where a lock must be held for the check but
 * should be released for the auditing.
 */
int avc_has_perm_noaudit(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                         struct av_decision *in_avd)
{
    struct avc_node *node;
    struct av_decision avd_entry, *avd;
    int rc = 0;
    u32 denied;

    BUG_ON(!requested);

    rcu_read_lock(&avc_rcu_lock);

    node = avc_lookup(ssid, tsid, tclass);
    if ( !node )
    {
        rcu_read_unlock(&avc_rcu_lock);

        if ( in_avd )
            avd = in_avd;
        else
            avd = &avd_entry;

        rc = security_compute_av(ssid,tsid,tclass,requested,avd);
        if ( rc )
            goto out;
        rcu_read_lock(&avc_rcu_lock);
        node = avc_insert(ssid,tsid,tclass,avd);
    } else {
        if ( in_avd )
            memcpy(in_avd, &node->ae.avd, sizeof(*in_avd));
        avd = &node->ae.avd;
    }

    denied = requested & ~(avd->allowed);

    if ( denied )
    {
        if ( !flask_enforcing || (avd->flags & AVD_FLAGS_PERMISSIVE) )
            avc_update_node(AVC_CALLBACK_GRANT,requested,
                            ssid,tsid,tclass,avd->seqno);
        else
            rc = -EACCES;
    }

    rcu_read_unlock(&avc_rcu_lock);
 out:
    return rc;
}

/**
 * avc_has_perm - Check permissions and perform any appropriate auditing.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @auditdata: auxiliary audit data
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Audit the granting or denial of
 * permissions in accordance with the policy.  Return %0 if all @requested
 * permissions are granted, -%EACCES if any permissions are denied, or
 * another -errno upon other errors.
 */
int avc_has_perm(u32 ssid, u32 tsid, u16 tclass,
                 u32 requested, struct avc_audit_data *auditdata)
{
    struct av_decision avd;
    int rc;

    rc = avc_has_perm_noaudit(ssid, tsid, tclass, requested, &avd);
    avc_audit(ssid, tsid, tclass, requested, &avd, rc, auditdata);
    return rc;
}
