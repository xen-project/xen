/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2010, Citrix Systems
 * Copyright (c) 2018-2019 BAE Systems
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/argo.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/nospec.h>
#include <xen/sched.h>
#include <xen/time.h>

#include <public/argo.h>

#ifdef CONFIG_COMPAT
#include <compat/argo.h>
CHECK_argo_addr;
CHECK_argo_ring;
#endif

DEFINE_XEN_GUEST_HANDLE(xen_argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_t);

static bool __read_mostly opt_argo;

static int __init parse_argo(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            opt_argo = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("argo", parse_argo);

typedef struct argo_ring_id
{
    xen_argo_port_t aport;
    domid_t partner_id;
    domid_t domain_id;
} argo_ring_id;

/* Data about a domain's own ring that it has registered */
struct argo_ring_info
{
    /* next node in the hash, protected by rings_L2 */
    struct list_head node;
    /* this ring's id, protected by rings_L2 */
    struct argo_ring_id id;
    /* L3, the ring_info lock: protects the members of this struct below */
    spinlock_t L3_lock;
    /* length of the ring, protected by L3 */
    unsigned int len;
    /* number of pages translated into mfns, protected by L3 */
    unsigned int nmfns;
    /* cached tx pointer location, protected by L3 */
    unsigned int tx_ptr;
    /* mapped ring pages protected by L3 */
    void **mfn_mapping;
    /* list of mfns of guest ring, protected by L3 */
    mfn_t *mfns;
    /* list of struct pending_ent for this ring, protected by L3 */
    struct list_head pending;
    /* number of pending entries queued for this ring, protected by L3 */
    unsigned int npending;
};

/* Data about a single-sender ring, held by the sender (partner) domain */
struct argo_send_info
{
    /* next node in the hash, protected by send_L2 */
    struct list_head node;
    /* this ring's id, protected by send_L2 */
    struct argo_ring_id id;
};

/* A space-available notification that is awaiting sufficient space */
struct pending_ent
{
    /* List node within argo_ring_info's pending list */
    struct list_head node;
    /*
     * List node within argo_domain's wildcard_pend_list. Only used if the
     * ring is one with a wildcard partner (ie. that any domain may send to)
     * to enable cancelling signals on wildcard rings on domain destroy.
     */
    struct list_head wildcard_node;
    /*
     * Pointer to the ring_info that this ent pertains to. Used to ensure that
     * ring_info->npending is decremented when ents for wildcard rings are
     * cancelled for domain destroy.
     * Caution: Must hold the correct locks before accessing ring_info via this.
     */
    struct argo_ring_info *ring_info;
    /* minimum ring space available that this signal is waiting upon */
    unsigned int len;
    /* domain to be notified when space is available */
    domid_t domain_id;
};

/*
 * The value of the argo element in a struct domain is
 * protected by L1_global_argo_rwlock
 */
#define ARGO_HASHTABLE_SIZE 32
struct argo_domain
{
    /* rings_L2 */
    rwlock_t rings_L2_rwlock;
    /*
     * Hash table of argo_ring_info about rings this domain has registered.
     * Protected by rings_L2.
     */
    struct list_head ring_hash[ARGO_HASHTABLE_SIZE];
    /* Counter of rings registered by this domain. Protected by rings_L2. */
    unsigned int ring_count;

    /* send_L2 */
    spinlock_t send_L2_lock;
    /*
     * Hash table of argo_send_info about rings other domains have registered
     * for this domain to send to. Single partner, non-wildcard rings.
     * Protected by send_L2.
     */
    struct list_head send_hash[ARGO_HASHTABLE_SIZE];

    /* wildcard_L2 */
    spinlock_t wildcard_L2_lock;
    /*
     * List of pending space-available signals for this domain about wildcard
     * rings registered by other domains. Protected by wildcard_L2.
     */
    struct list_head wildcard_pend_list;
};

/*
 * Locking is organized as follows:
 *
 * Terminology: R(<lock>) means taking a read lock on the specified lock;
 *              W(<lock>) means taking a write lock on it.
 *
 * == L1 : The global read/write lock: L1_global_argo_rwlock
 * Protects the argo elements of all struct domain *d in the system.
 *
 * R(L1) does not protect any of the elements of d->argo; it protects their
 * addresses. W(L1) protects those and more since it implies W on all the lower
 * level locks - see the notes on those locks below.
 *
 * The destruction of an argo-enabled domain, which must have a non-NULL d->argo
 * pointer, will need to free that d->argo pointer, which requires W(L1).
 * Since holding R(L1) will block acquiring W(L1), it will ensure that
 * no domains pointers that argo is interested in become invalid while either
 * W(L1) or R(L1) are held.
 */

static DEFINE_RWLOCK(L1_global_argo_rwlock); /* L1 */

/*
 * == rings_L2 : The per-domain ring hash lock: d->argo->rings_L2_rwlock
 *
 * Holding a read lock on rings_L2 protects the ring hash table and
 * the elements in the hash_table d->argo->ring_hash, and
 * the node and id fields in struct argo_ring_info in the
 * hash table.
 * Holding a write lock on rings_L2 protects all of the elements of all the
 * struct argo_ring_info belonging to this domain.
 *
 * To take rings_L2 you must already have R(L1). W(L1) implies W(rings_L2) and
 * L3.
 *
 * == L3 : The individual ring_info lock: ring_info->L3_lock
 *
 * Protects all the fields within the argo_ring_info, aside from the ones that
 * rings_L2 already protects: node, id, lock.
 *
 * To acquire L3 you must already have R(rings_L2). W(rings_L2) implies L3.
 *
 * == send_L2 : The per-domain single-sender partner rings lock:
 *              d->argo->send_L2_lock
 *
 * Protects the per-domain send hash table : d->argo->send_hash
 * and the elements in the hash table, and the node and id fields
 * in struct argo_send_info in the hash table.
 *
 * To take send_L2, you must already have R(L1). W(L1) implies send_L2.
 * Do not attempt to acquire a rings_L2 on any domain after taking and while
 * holding a send_L2 lock -- acquire the rings_L2 (if one is needed) beforehand.
 *
 * == wildcard_L2 : The per-domain wildcard pending list lock:
 *                  d->argo->wildcard_L2_lock
 *
 * Protects the per-domain list of outstanding signals for space availability
 * on wildcard rings.
 *
 * To take wildcard_L2, you must already have R(L1). W(L1) implies wildcard_L2.
 * No other locks are acquired after obtaining wildcard_L2.
 */

/*
 * Lock state validations macros
 *
 * These macros encode the logic to verify that the locking has adhered to the
 * locking discipline above.
 * eg. On entry to logic that requires holding at least R(rings_L2), this:
 *      ASSERT(LOCKING_Read_rings_L2(d));
 *
 * checks that the lock state is sufficient, validating that one of the
 * following must be true when executed:       R(rings_L2) && R(L1)
 *                                        or:  W(rings_L2) && R(L1)
 *                                        or:  W(L1)
 *
 * The LOCKING macros defined below here are for use at verification points.
 */
#define LOCKING_Write_L1 (rw_is_write_locked(&L1_global_argo_rwlock))
/*
 * While LOCKING_Read_L1 will return true even if the lock is write-locked,
 * that's OK because everywhere that a Read lock is needed with these macros,
 * holding a Write lock there instead is OK too: we're checking that _at least_
 * the specified level of locks are held.
 */
#define LOCKING_Read_L1 (rw_is_locked(&L1_global_argo_rwlock))

#define LOCKING_Write_rings_L2(d) \
    ((LOCKING_Read_L1 && rw_is_write_locked(&(d)->argo->rings_L2_rwlock)) || \
     LOCKING_Write_L1)
/*
 * Skip checking LOCKING_Write_rings_L2(d) within this LOCKING_Read_rings_L2
 * definition because the first clause that is testing R(L1) && R(L2) will also
 * return true if R(L1) && W(L2) is true, because of the way that rw_is_locked
 * behaves. This results in a slightly shorter and faster implementation.
 */
#define LOCKING_Read_rings_L2(d) \
    ((LOCKING_Read_L1 && rw_is_locked(&(d)->argo->rings_L2_rwlock)) || \
     LOCKING_Write_L1)
/*
 * Skip checking LOCKING_Write_L1 within this LOCKING_L3 definition because
 * LOCKING_Write_rings_L2(d) will return true for that condition.
 */
#define LOCKING_L3(d, r) \
    ((LOCKING_Read_L1 && rw_is_locked(&(d)->argo->rings_L2_rwlock) \
      && spin_is_locked(&(r)->L3_lock)) || LOCKING_Write_rings_L2(d))

#define LOCKING_send_L2(d) \
    ((LOCKING_Read_L1 && spin_is_locked(&(d)->argo->send_L2_lock)) || \
     LOCKING_Write_L1)

/* Change this to #define ARGO_DEBUG here to enable more debug messages */
#undef ARGO_DEBUG

#ifdef ARGO_DEBUG
#define argo_dprintk(format, args...) printk("argo: " format, ## args )
#else
#define argo_dprintk(format, ... ) ((void)0)
#endif

/*
 * This hash function is used to distribute rings within the per-domain
 * hash tables (d->argo->ring_hash and d->argo_send_hash). The hash table
 * will provide a struct if a match is found with a 'argo_ring_id' key:
 * ie. the key is a (domain id, argo port, partner domain id) tuple.
 * The algorithm approximates the string hashing function 'djb2'.
 */
static unsigned int
hash_index(const struct argo_ring_id *id)
{
    unsigned int hash = 5381; /* prime constant from djb2 */

    /* For each input: hash = hash * 33 + <new input character value> */
    hash = ((hash << 5) + hash) +  (id->aport            & 0xff);
    hash = ((hash << 5) + hash) + ((id->aport      >> 8) & 0xff);
    hash = ((hash << 5) + hash) + ((id->aport     >> 16) & 0xff);
    hash = ((hash << 5) + hash) + ((id->aport     >> 24) & 0xff);
    hash = ((hash << 5) + hash) +  (id->domain_id        & 0xff);
    hash = ((hash << 5) + hash) + ((id->domain_id  >> 8) & 0xff);
    hash = ((hash << 5) + hash) +  (id->partner_id       & 0xff);
    hash = ((hash << 5) + hash) + ((id->partner_id >> 8) & 0xff);

    /*
     * Since ARGO_HASHTABLE_SIZE is small, use higher-order bits of the
     * hash to contribute to the lower-order bits before masking off.
     */
    return (hash ^ (hash >> 15)) & (ARGO_HASHTABLE_SIZE - 1);
}

static struct argo_ring_info *
find_ring_info(const struct domain *d, const struct argo_ring_id *id)
{
    struct argo_ring_info *ring_info;
    const struct list_head *bucket;

    ASSERT(LOCKING_Read_rings_L2(d));

    /* List is not modified here. Search and return the match if found. */
    bucket = &d->argo->ring_hash[hash_index(id)];

    list_for_each_entry(ring_info, bucket, node)
    {
        const struct argo_ring_id *cmpid = &ring_info->id;

        if ( cmpid->aport == id->aport &&
             cmpid->domain_id == id->domain_id &&
             cmpid->partner_id == id->partner_id )
        {
            argo_dprintk("found ring_info for ring(%u:%x %u)\n",
                         id->domain_id, id->aport, id->partner_id);
            return ring_info;
        }
    }
    argo_dprintk("no ring_info for ring(%u:%x %u)\n",
                 id->domain_id, id->aport, id->partner_id);

    return NULL;
}

static void
ring_unmap(const struct domain *d, struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(LOCKING_L3(d, ring_info));

    if ( !ring_info->mfn_mapping )
        return;

    ASSERT(!ring_info->nmfns || ring_info->mfns);

    for ( i = 0; i < ring_info->nmfns; i++ )
    {
        if ( !ring_info->mfn_mapping[i] )
            continue;

        ASSERT(!mfn_eq(ring_info->mfns[i], INVALID_MFN));
        argo_dprintk(XENLOG_ERR "argo: unmapping page %"PRI_mfn" from %p\n",
                     mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);

        unmap_domain_page_global(ring_info->mfn_mapping[i]);
        ring_info->mfn_mapping[i] = NULL;
    }
}

static void
wildcard_pending_list_remove(domid_t domain_id, struct pending_ent *ent)
{
    struct domain *d = get_domain_by_id(domain_id);

    if ( !d )
        return;

    ASSERT(LOCKING_Read_L1);

    if ( d->argo )
    {
        spin_lock(&d->argo->wildcard_L2_lock);
        list_del(&ent->wildcard_node);
        spin_unlock(&d->argo->wildcard_L2_lock);
    }
    put_domain(d);
}

static void
pending_remove_all(const struct domain *d, struct argo_ring_info *ring_info)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_L3(d, ring_info));

    /* Delete all pending notifications from this ring's list. */
    while ( (ent = list_first_entry_or_null(&ring_info->pending,
                                            struct pending_ent, node)) )
    {
        /* For wildcard rings, remove each from their wildcard list too. */
        if ( ring_info->id.partner_id == XEN_ARGO_DOMID_ANY )
            wildcard_pending_list_remove(ent->domain_id, ent);
        list_del(&ent->node);
        xfree(ent);
    }
    ring_info->npending = 0;
}

static void
wildcard_rings_pending_remove(struct domain *d)
{
    struct pending_ent *ent;

    ASSERT(LOCKING_Write_L1);

    /* Delete all pending signals to the domain about wildcard rings. */
    while ( (ent = list_first_entry_or_null(&d->argo->wildcard_pend_list,
                                            struct pending_ent, node)) )
    {
        /*
         * The ent->node deleted here, and the npending value decreased,
         * belong to the ring_info of another domain, which is why this
         * function requires holding W(L1):
         * it implies the L3 lock that protects that ring_info struct.
         */
        ent->ring_info->npending--;
        list_del(&ent->node);
        list_del(&ent->wildcard_node);
        xfree(ent);
    }
}

static void
ring_remove_mfns(const struct domain *d, struct argo_ring_info *ring_info)
{
    unsigned int i;

    ASSERT(LOCKING_Write_rings_L2(d));

    if ( !ring_info->mfns )
        return;

    if ( !ring_info->mfn_mapping )
    {
        ASSERT_UNREACHABLE();
        return;
    }

    ring_unmap(d, ring_info);

    for ( i = 0; i < ring_info->nmfns; i++ )
        if ( !mfn_eq(ring_info->mfns[i], INVALID_MFN) )
            put_page_and_type(mfn_to_page(ring_info->mfns[i]));

    ring_info->nmfns = 0;
    XFREE(ring_info->mfns);
    XFREE(ring_info->mfn_mapping);
}

static void
ring_remove_info(const struct domain *d, struct argo_ring_info *ring_info)
{
    ASSERT(LOCKING_Write_rings_L2(d));

    pending_remove_all(d, ring_info);
    list_del(&ring_info->node);
    ring_remove_mfns(d, ring_info);
    xfree(ring_info);
}

static void
domain_rings_remove_all(struct domain *d)
{
    unsigned int i;

    ASSERT(LOCKING_Write_rings_L2(d));

    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
    {
        struct argo_ring_info *ring_info;
        struct list_head *bucket = &d->argo->ring_hash[i];

        while ( (ring_info = list_first_entry_or_null(bucket,
                                                      struct argo_ring_info,
                                                      node)) )
            ring_remove_info(d, ring_info);
    }
    d->argo->ring_count = 0;
}

/*
 * Tear down all rings of other domains where src_d domain is the partner.
 * (ie. it is the single domain that can send to those rings.)
 * This will also cancel any pending notifications about those rings.
 */
static void
partner_rings_remove(struct domain *src_d)
{
    unsigned int i;

    ASSERT(LOCKING_Write_L1);

    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
    {
        struct argo_send_info *send_info;
        struct list_head *bucket = &src_d->argo->send_hash[i];

        /* Remove all ents from the send list. Take each off their ring list. */
        while ( (send_info = list_first_entry_or_null(bucket,
                                                      struct argo_send_info,
                                                      node)) )
        {
            struct domain *dst_d = get_domain_by_id(send_info->id.domain_id);

            if ( dst_d && dst_d->argo )
            {
                struct argo_ring_info *ring_info =
                    find_ring_info(dst_d, &send_info->id);

                if ( ring_info )
                {
                    ring_remove_info(dst_d, ring_info);
                    dst_d->argo->ring_count--;
                }
                else
                    ASSERT_UNREACHABLE();
            }
            else
                ASSERT_UNREACHABLE();

            if ( dst_d )
                put_domain(dst_d);

            list_del(&send_info->node);
            xfree(send_info);
        }
    }
}

long
do_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
           XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long raw_arg3,
           unsigned long raw_arg4)
{
    long rc;
    unsigned int arg3 = raw_arg3, arg4 = raw_arg4;

    argo_dprintk("->do_argo_op(%u,%p,%p,%lu,0x%lx)\n", cmd,
                 (void *)arg1.p, (void *)arg2.p, raw_arg3, raw_arg4);

    /* Reject numeric hypercall args outside 32-bit range */
    if ( (arg3 != raw_arg3) || (arg4 != raw_arg4) )
        return -EINVAL;

    if ( unlikely(!opt_argo) )
        return -EOPNOTSUPP;

    switch ( cmd )
    {
    default:
        rc = -EOPNOTSUPP;
        break;
    }

    argo_dprintk("<-do_argo_op(%u)=%ld\n", cmd, rc);

    return rc;
}

#ifdef CONFIG_COMPAT
long
compat_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
               XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long arg3,
               unsigned long arg4)
{
    /* Forward all ops to the native handler */
    return do_argo_op(cmd, arg1, arg2, arg3, arg4);
}
#endif

static void
argo_domain_init(struct argo_domain *argo)
{
    unsigned int i;

    rwlock_init(&argo->rings_L2_rwlock);
    spin_lock_init(&argo->send_L2_lock);
    spin_lock_init(&argo->wildcard_L2_lock);

    for ( i = 0; i < ARGO_HASHTABLE_SIZE; ++i )
    {
        INIT_LIST_HEAD(&argo->ring_hash[i]);
        INIT_LIST_HEAD(&argo->send_hash[i]);
    }
    INIT_LIST_HEAD(&argo->wildcard_pend_list);
}

int
argo_init(struct domain *d)
{
    struct argo_domain *argo;

    if ( !opt_argo )
    {
        argo_dprintk("argo disabled, domid: %u\n", d->domain_id);
        return 0;
    }

    argo_dprintk("init: domid: %u\n", d->domain_id);

    argo = xzalloc(struct argo_domain);
    if ( !argo )
        return -ENOMEM;

    argo_domain_init(argo);

    write_lock(&L1_global_argo_rwlock);

    d->argo = argo;

    write_unlock(&L1_global_argo_rwlock);

    return 0;
}

void
argo_destroy(struct domain *d)
{
    BUG_ON(!d->is_dying);

    write_lock(&L1_global_argo_rwlock);

    argo_dprintk("destroy: domid %u d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        partner_rings_remove(d);
        wildcard_rings_pending_remove(d);
        XFREE(d->argo);
    }

    write_unlock(&L1_global_argo_rwlock);
}

void
argo_soft_reset(struct domain *d)
{
    write_lock(&L1_global_argo_rwlock);

    argo_dprintk("soft reset d=%u d->argo=%p\n", d->domain_id, d->argo);

    if ( d->argo )
    {
        domain_rings_remove_all(d);
        partner_rings_remove(d);
        wildcard_rings_pending_remove(d);

        /*
         * Since opt_argo cannot change at runtime, if d->argo is true then
         * opt_argo must be true, and we can assume that init is allowed to
         * proceed again here.
         */
        argo_domain_init(d->argo);
    }

    write_unlock(&L1_global_argo_rwlock);
}
