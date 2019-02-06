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
#include <xen/lib.h>
#include <xen/nospec.h>
#include <xen/sched.h>
#include <xen/time.h>

#include <public/argo.h>

#ifdef CONFIG_COMPAT
#include <compat/argo.h>
CHECK_argo_addr;
#undef CHECK_argo_addr
#define CHECK_argo_addr struct xen_argo_addr
CHECK_argo_register_ring;
CHECK_argo_ring;
CHECK_argo_ring_message_header;
CHECK_argo_unregister_ring;
#endif

#define MAX_RINGS_PER_DOMAIN            128U

/* All messages on the ring are padded to a multiple of the slot size. */
#define ROUNDUP_MESSAGE(a) ROUNDUP((a), XEN_ARGO_MSG_SLOT_SIZE)

/* Number of PAGEs needed to hold a ring of a given size in bytes */
#define NPAGES_RING(ring_len) \
    (ROUNDUP((ROUNDUP_MESSAGE(ring_len) + sizeof(xen_argo_ring_t)), PAGE_SIZE) \
     >> PAGE_SHIFT)

DEFINE_XEN_GUEST_HANDLE(xen_argo_addr_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_gfn_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_register_ring_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_ring_t);
DEFINE_XEN_GUEST_HANDLE(xen_argo_unregister_ring_t);

static bool __read_mostly opt_argo;
static bool __read_mostly opt_argo_mac_permissive;

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
        else if ( (val = parse_boolean("mac-permissive", s, ss)) >= 0 )
            opt_argo_mac_permissive = val;
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

static struct argo_send_info *
find_send_info(const struct domain *d, const struct argo_ring_id *id)
{
    struct argo_send_info *send_info;
    const struct list_head *bucket;

    ASSERT(LOCKING_send_L2(d));

    /* List is not modified here. Search and return the match if found. */
    bucket = &d->argo->send_hash[hash_index(id)];

    list_for_each_entry(send_info, bucket, node)
    {
        const struct argo_ring_id *cmpid = &send_info->id;

        if ( cmpid->aport == id->aport &&
             cmpid->domain_id == id->domain_id &&
             cmpid->partner_id == id->partner_id )
        {
            argo_dprintk("found send_info for ring(%u:%x %u)\n",
                         id->domain_id, id->aport, id->partner_id);
            return send_info;
        }
    }
    argo_dprintk("no send_info for ring(%u:%x %u)\n",
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

static int
ring_map_page(const struct domain *d, struct argo_ring_info *ring_info,
              unsigned int i, void **out_ptr)
{
    ASSERT(LOCKING_L3(d, ring_info));

    /*
     * FIXME: Investigate using vmap to create a single contiguous virtual
     * address space mapping of the ring instead of using the array of single
     * page mappings.
     * Affects logic in memcpy_to_guest_ring, the mfn_mapping array data
     * structure, and places where ring mappings are added or removed.
     */

    if ( i >= ring_info->nmfns )
    {
        gprintk(XENLOG_ERR,
               "argo: ring (vm%u:%x vm%u) %p attempted to map page %u of %u\n",
                ring_info->id.domain_id, ring_info->id.aport,
                ring_info->id.partner_id, ring_info, i, ring_info->nmfns);
        return -ENOMEM;
    }
    i = array_index_nospec(i, ring_info->nmfns);

    if ( !ring_info->mfns || !ring_info->mfn_mapping )
    {
        ASSERT_UNREACHABLE();
        ring_info->len = 0;
        return -ENOMEM;
    }

    if ( !ring_info->mfn_mapping[i] )
    {
        ring_info->mfn_mapping[i] = map_domain_page_global(ring_info->mfns[i]);
        if ( !ring_info->mfn_mapping[i] )
        {
            gprintk(XENLOG_ERR, "argo: ring (vm%u:%x vm%u) %p attempted to map "
                    "page %u of %u\n",
                    ring_info->id.domain_id, ring_info->id.aport,
                    ring_info->id.partner_id, ring_info, i, ring_info->nmfns);
            return -ENOMEM;
        }
        argo_dprintk("mapping page %"PRI_mfn" to %p\n",
                     mfn_x(ring_info->mfns[i]), ring_info->mfn_mapping[i]);
    }

    if ( out_ptr )
        *out_ptr = ring_info->mfn_mapping[i];

    return 0;
}

static void
update_tx_ptr(const struct domain *d, struct argo_ring_info *ring_info,
              uint32_t tx_ptr)
{
    xen_argo_ring_t *ringp;

    ASSERT(LOCKING_L3(d, ring_info));
    ASSERT(ring_info->mfn_mapping[0]);

    ring_info->tx_ptr = tx_ptr;
    ringp = ring_info->mfn_mapping[0];

    write_atomic(&ringp->tx_ptr, tx_ptr);
    smp_wmb();
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

static int
find_ring_mfn(struct domain *d, gfn_t gfn, mfn_t *mfn)
{
    struct page_info *page;
    p2m_type_t p2mt;
    int ret;

    ret = check_get_page_from_gfn(d, gfn, false, &p2mt, &page);
    if ( unlikely(ret) )
        return ret;

    *mfn = page_to_mfn(page);
    if ( !mfn_valid(*mfn) )
        ret = -EINVAL;
#ifdef CONFIG_X86
    else if ( p2mt == p2m_ram_logdirty )
        ret = -EAGAIN;
#endif
    else if ( (p2mt != p2m_ram_rw) ||
              !get_page_and_type(page, d, PGT_writable_page) )
        ret = -EINVAL;

    put_page(page);

    return ret;
}

static int
find_ring_mfns(struct domain *d, struct argo_ring_info *ring_info,
               const unsigned int npage,
               XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd,
               const unsigned int len)
{
    unsigned int i;
    int ret = 0;
    mfn_t *mfns;
    void **mfn_mapping;

    ASSERT(LOCKING_Write_rings_L2(d));

    if ( ring_info->mfns )
    {
        /* Ring already existed: drop the previous mapping. */
        gprintk(XENLOG_INFO, "argo: vm%u re-register existing ring "
                "(vm%u:%x vm%u) clears mapping\n",
                d->domain_id, ring_info->id.domain_id,
                ring_info->id.aport, ring_info->id.partner_id);

        ring_remove_mfns(d, ring_info);
        ASSERT(!ring_info->mfns);
    }

    mfns = xmalloc_array(mfn_t, npage);
    if ( !mfns )
        return -ENOMEM;

    for ( i = 0; i < npage; i++ )
        mfns[i] = INVALID_MFN;

    mfn_mapping = xzalloc_array(void *, npage);
    if ( !mfn_mapping )
    {
        xfree(mfns);
        return -ENOMEM;
    }

    ring_info->mfns = mfns;
    ring_info->mfn_mapping = mfn_mapping;

    for ( i = 0; i < npage; i++ )
    {
        mfn_t mfn;
        xen_argo_gfn_t argo_gfn;

        ret = __copy_from_guest_offset(&argo_gfn, gfn_hnd, i, 1) ? -EFAULT : 0;
        if ( ret )
            break;

        ret = find_ring_mfn(d, _gfn(argo_gfn), &mfn);
        if ( ret )
        {
            gprintk(XENLOG_ERR, "argo: vm%u: invalid gfn %"PRI_gfn" "
                    "r:(vm%u:%x vm%u) %p %u/%u\n",
                    d->domain_id, gfn_x(_gfn(argo_gfn)),
                    ring_info->id.domain_id, ring_info->id.aport,
                    ring_info->id.partner_id, ring_info, i, npage);
            break;
        }

        ring_info->mfns[i] = mfn;

        argo_dprintk("%u: %"PRI_gfn" -> %"PRI_mfn"\n",
                     i, gfn_x(_gfn(argo_gfn)), mfn_x(ring_info->mfns[i]));
    }

    ring_info->nmfns = i;

    if ( ret )
        ring_remove_mfns(d, ring_info);
    else
    {
        ASSERT(ring_info->nmfns == NPAGES_RING(len));

        gprintk(XENLOG_DEBUG, "argo: vm%u ring (vm%u:%x vm%u) %p "
                "mfn_mapping %p len %u nmfns %u\n",
                d->domain_id, ring_info->id.domain_id,
                ring_info->id.aport, ring_info->id.partner_id, ring_info,
                ring_info->mfn_mapping, ring_info->len, ring_info->nmfns);
    }

    return ret;
}

static long
unregister_ring(struct domain *currd,
                XEN_GUEST_HANDLE_PARAM(xen_argo_unregister_ring_t) unreg_hnd)
{
    xen_argo_unregister_ring_t unreg;
    struct argo_ring_id ring_id;
    struct argo_ring_info *ring_info = NULL;
    struct argo_send_info *send_info = NULL;
    struct domain *dst_d = NULL;

    ASSERT(currd == current->domain);

    if ( copy_from_guest(&unreg, unreg_hnd, 1) )
        return -EFAULT;

    if ( unreg.pad )
        return -EINVAL;

    ring_id.partner_id = unreg.partner_id;
    ring_id.aport = unreg.aport;
    ring_id.domain_id = currd->domain_id;

    read_lock(&L1_global_argo_rwlock);

    if ( unlikely(!currd->argo) )
    {
        read_unlock(&L1_global_argo_rwlock);
        return -ENODEV;
    }

    write_lock(&currd->argo->rings_L2_rwlock);

    ring_info = find_ring_info(currd, &ring_id);
    if ( !ring_info )
        goto out;

    ring_remove_info(currd, ring_info);
    currd->argo->ring_count--;

    if ( ring_id.partner_id == XEN_ARGO_DOMID_ANY )
        goto out;

    dst_d = get_domain_by_id(ring_id.partner_id);
    if ( !dst_d || !dst_d->argo )
    {
        ASSERT_UNREACHABLE();
        goto out;
    }

    spin_lock(&dst_d->argo->send_L2_lock);

    send_info = find_send_info(dst_d, &ring_id);
    if ( send_info )
        list_del(&send_info->node);
    else
        ASSERT_UNREACHABLE();

    spin_unlock(&dst_d->argo->send_L2_lock);

 out:
    write_unlock(&currd->argo->rings_L2_rwlock);

    read_unlock(&L1_global_argo_rwlock);

    if ( dst_d )
        put_domain(dst_d);

    xfree(send_info);

    if ( !ring_info )
    {
        argo_dprintk("unregister_ring: no ring_info found for ring(%u:%x %u)\n",
                     ring_id.domain_id, ring_id.aport, ring_id.partner_id);
        return -ENOENT;
    }

    return 0;
}

static long
register_ring(struct domain *currd,
              XEN_GUEST_HANDLE_PARAM(xen_argo_register_ring_t) reg_hnd,
              XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd,
              unsigned int npage, unsigned int flags)
{
    xen_argo_register_ring_t reg;
    struct argo_ring_id ring_id;
    void *map_ringp;
    xen_argo_ring_t *ringp;
    struct argo_ring_info *ring_info, *new_ring_info = NULL;
    struct argo_send_info *send_info = NULL;
    struct domain *dst_d = NULL;
    int ret = 0;
    unsigned int private_tx_ptr;

    ASSERT(currd == current->domain);

    /* flags: reserve currently-undefined bits, require zero.  */
    if ( unlikely(flags & ~XEN_ARGO_REGISTER_FLAG_MASK) )
        return -EINVAL;

    if ( copy_from_guest(&reg, reg_hnd, 1) )
        return -EFAULT;

    /*
     * A ring must be large enough to transmit messages, so requires space for:
     * * 1 message header, plus
     * * 1 payload slot (payload is always rounded to a multiple of 16 bytes)
     *   for the message payload to be written into, plus
     * * 1 more slot, so that the ring cannot be filled to capacity with a
     *   single minimum-size message -- see the logic in ringbuf_insert --
     *   allowing for this ensures that there can be space remaining when a
     *   message is present.
     * The above determines the minimum acceptable ring size.
     */
    if ( (reg.len < (sizeof(struct xen_argo_ring_message_header)
                      + ROUNDUP_MESSAGE(1) + ROUNDUP_MESSAGE(1))) ||
         (reg.len > XEN_ARGO_MAX_RING_SIZE) ||
         (reg.len != ROUNDUP_MESSAGE(reg.len)) ||
         (NPAGES_RING(reg.len) != npage) ||
         (reg.pad != 0) )
        return -EINVAL;

    ring_id.partner_id = reg.partner_id;
    ring_id.aport = reg.aport;
    ring_id.domain_id = currd->domain_id;

    if ( reg.partner_id == XEN_ARGO_DOMID_ANY )
    {
        if ( !opt_argo_mac_permissive )
            return -EPERM;
    }
    else
    {
        dst_d = get_domain_by_id(reg.partner_id);
        if ( !dst_d )
        {
            argo_dprintk("!dst_d, ESRCH\n");
            return -ESRCH;
        }

        send_info = xzalloc(struct argo_send_info);
        if ( !send_info )
        {
            ret = -ENOMEM;
            goto out;
        }
        send_info->id = ring_id;
    }

    /*
     * Common case is that the ring doesn't already exist, so do the alloc here
     * before picking up any locks.
     */
    new_ring_info = xzalloc(struct argo_ring_info);
    if ( !new_ring_info )
    {
        ret = -ENOMEM;
        goto out;
    }

    read_lock(&L1_global_argo_rwlock);

    if ( !currd->argo )
    {
        ret = -ENODEV;
        goto out_unlock;
    }

    if ( dst_d && !dst_d->argo )
    {
        argo_dprintk("!dst_d->argo, ECONNREFUSED\n");
        ret = -ECONNREFUSED;
        goto out_unlock;
    }

    write_lock(&currd->argo->rings_L2_rwlock);

    if ( currd->argo->ring_count >= MAX_RINGS_PER_DOMAIN )
    {
        ret = -ENOSPC;
        goto out_unlock2;
    }

    ring_info = find_ring_info(currd, &ring_id);
    if ( !ring_info )
    {
        ring_info = new_ring_info;
        new_ring_info = NULL;

        spin_lock_init(&ring_info->L3_lock);

        ring_info->id = ring_id;
        INIT_LIST_HEAD(&ring_info->pending);

        list_add(&ring_info->node,
                 &currd->argo->ring_hash[hash_index(&ring_info->id)]);

        gprintk(XENLOG_DEBUG, "argo: vm%u registering ring (vm%u:%x vm%u)\n",
                currd->domain_id, ring_id.domain_id, ring_id.aport,
                ring_id.partner_id);
    }
    else if ( ring_info->len )
    {
        /*
         * If the caller specified that the ring must not already exist,
         * fail at attempt to add a completed ring which already exists.
         */
        if ( flags & XEN_ARGO_REGISTER_FLAG_FAIL_EXIST )
        {
            gprintk(XENLOG_ERR, "argo: vm%u disallowed reregistration of "
                    "existing ring (vm%u:%x vm%u)\n",
                    currd->domain_id, ring_id.domain_id, ring_id.aport,
                    ring_id.partner_id);
            ret = -EEXIST;
            goto out_unlock2;
        }

        if ( ring_info->len != reg.len )
        {
            /*
             * Change of ring size could result in entries on the pending
             * notifications list that will never trigger.
             * Simple blunt solution: disallow ring resize for now.
             * TODO: investigate enabling ring resize.
             */
            gprintk(XENLOG_ERR, "argo: vm%u attempted to change ring size "
                    "(vm%u:%x vm%u)\n",
                    currd->domain_id, ring_id.domain_id, ring_id.aport,
                    ring_id.partner_id);
            /*
             * Could return EINVAL here, but if the ring didn't already
             * exist then the arguments would have been valid, so: EEXIST.
             */
            ret = -EEXIST;
            goto out_unlock2;
        }

        gprintk(XENLOG_DEBUG,
                "argo: vm%u re-registering existing ring (vm%u:%x vm%u)\n",
                currd->domain_id, ring_id.domain_id, ring_id.aport,
                ring_id.partner_id);
    }

    ret = find_ring_mfns(currd, ring_info, npage, gfn_hnd, reg.len);
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u failed to find ring mfns (vm%u:%x vm%u)\n",
                currd->domain_id, ring_id.domain_id, ring_id.aport,
                ring_id.partner_id);

        ring_remove_info(currd, ring_info);
        goto out_unlock2;
    }

    /*
     * The first page of the memory supplied for the ring has the xen_argo_ring
     * structure at its head, which is where the ring indexes reside.
     */
    ret = ring_map_page(currd, ring_info, 0, &map_ringp);
    if ( ret )
    {
        gprintk(XENLOG_ERR,
                "argo: vm%u failed to map ring mfn 0 (vm%u:%x vm%u)\n",
                currd->domain_id, ring_id.domain_id, ring_id.aport,
                ring_id.partner_id);

        ring_remove_info(currd, ring_info);
        goto out_unlock2;
    }
    ringp = map_ringp;

    private_tx_ptr = read_atomic(&ringp->tx_ptr);

    if ( (private_tx_ptr >= reg.len) ||
         (ROUNDUP_MESSAGE(private_tx_ptr) != private_tx_ptr) )
    {
        /*
         * Since the ring is a mess, attempt to flush the contents of it
         * here by setting the tx_ptr to the next aligned message slot past
         * the latest rx_ptr we have observed. Handle ring wrap correctly.
         */
        private_tx_ptr = ROUNDUP_MESSAGE(read_atomic(&ringp->rx_ptr));

        if ( private_tx_ptr >= reg.len )
            private_tx_ptr = 0;

        update_tx_ptr(currd, ring_info, private_tx_ptr);
    }

    ring_info->tx_ptr = private_tx_ptr;
    ring_info->len = reg.len;
    currd->argo->ring_count++;

    if ( send_info )
    {
        spin_lock(&dst_d->argo->send_L2_lock);

        list_add(&send_info->node,
                 &dst_d->argo->send_hash[hash_index(&send_info->id)]);

        spin_unlock(&dst_d->argo->send_L2_lock);
    }

 out_unlock2:
    write_unlock(&currd->argo->rings_L2_rwlock);

 out_unlock:
    read_unlock(&L1_global_argo_rwlock);

 out:
    if ( dst_d )
        put_domain(dst_d);

    if ( ret )
        xfree(send_info);

    xfree(new_ring_info);

    return ret;
}

long
do_argo_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg1,
           XEN_GUEST_HANDLE_PARAM(void) arg2, unsigned long raw_arg3,
           unsigned long raw_arg4)
{
    struct domain *currd = current->domain;
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
    case XEN_ARGO_OP_register_ring:
    {
        XEN_GUEST_HANDLE_PARAM(xen_argo_register_ring_t) reg_hnd =
            guest_handle_cast(arg1, xen_argo_register_ring_t);
        XEN_GUEST_HANDLE_PARAM(xen_argo_gfn_t) gfn_hnd =
            guest_handle_cast(arg2, xen_argo_gfn_t);
        /* arg3: npage, arg4: flags */

        BUILD_BUG_ON(!IS_ALIGNED(XEN_ARGO_MAX_RING_SIZE, PAGE_SIZE));

        if ( unlikely(arg3 > (XEN_ARGO_MAX_RING_SIZE >> PAGE_SHIFT)) )
        {
            rc = -EINVAL;
            break;
        }

        /* Check array to allow use of the faster __copy operations later */
        if ( unlikely(!guest_handle_okay(gfn_hnd, arg3)) )
        {
            rc = -EFAULT;
            break;
        }

        rc = register_ring(currd, reg_hnd, gfn_hnd, arg3, arg4);
        break;
    }

    case XEN_ARGO_OP_unregister_ring:
    {
        XEN_GUEST_HANDLE_PARAM(xen_argo_unregister_ring_t) unreg_hnd =
            guest_handle_cast(arg1, xen_argo_unregister_ring_t);

        if ( unlikely((!guest_handle_is_null(arg2)) || arg3 || arg4) )
        {
            rc = -EINVAL;
            break;
        }

        rc = unregister_ring(currd, unreg_hnd);
        break;
    }

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
