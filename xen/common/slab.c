/*
 * linux/mm/slab.c
 * Written by Mark Hemment, 1996/97.
 * (markhe@nextd.demon.co.uk)
 *
 * xmem_cache_destroy() + some cleanup - 1999 Andrea Arcangeli
 *
 * Major cleanup, different bufctl logic, per-cpu arrays
 *	(c) 2000 Manfred Spraul
 *
 * An implementation of the Slab Allocator as described in outline in;
 *	UNIX Internals: The New Frontiers by Uresh Vahalia
 *	Pub: Prentice Hall	ISBN 0-13-101908-2
 * or with a little more detail in;
 *	The Slab Allocator: An Object-Caching Kernel Memory Allocator
 *	Jeff Bonwick (Sun Microsystems).
 *	Presented at: USENIX Summer 1994 Technical Conference
 *
 *
 * The memory is organized in caches, one cache for each object type.
 * (e.g. inode_cache, dentry_cache, buffer_head, vm_area_struct)
 * Each cache consists out of many slabs (they are small (usually one
 * page long) and always contiguous), and each slab contains multiple
 * initialized objects.
 *
 * In order to reduce fragmentation, the slabs are sorted in 3 groups:
 *   full slabs with 0 free objects
 *   partial slabs
 *   empty slabs with no allocated objects
 *
 * If partial slabs exist, then new allocations come from these slabs,
 * otherwise from empty slabs or new slabs are allocated.
 *
 * xmem_cache_destroy() CAN CRASH if you try to allocate from the cache
 * during xmem_cache_destroy(). The caller must prevent concurrent allocs.
 *
 * On SMP systems, each cache has a short per-cpu head array, most allocs
 * and frees go into that array, and if that array overflows, then 1/2
 * of the entries in the array are given back into the global cache.
 * This reduces the number of spinlock operations.
 *
 * The c_cpuarray may not be read with enabled local interrupts.
 *
 * SMP synchronization:
 *  constructors and destructors are called without any locking.
 *  Several members in xmem_cache_t and slab_t never change, they
 *	are accessed without any locking.
 *  The per-cpu arrays are never accessed from the wrong cpu, no locking.
 *  The non-constant members are protected with a per-cache irq spinlock.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/slab.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/errno.h>
#include <xen/smp.h>
#include <xen/sched.h>

/*
 * DEBUG  - 1 for xmem_cache_create() to honour; SLAB_DEBUG_INITIAL,
 *	    SLAB_RED_ZONE & SLAB_POISON.
 *	    0 for faster, smaller code (especially in the critical paths).
 *
 * STATS  - 1 to collect stats for /proc/slabinfo.
 *	    0 for faster, smaller code (especially in the critical paths).
 *
 * FORCED_DEBUG	- 1 enables SLAB_RED_ZONE and SLAB_POISON (if possible)
 */
#ifdef CONFIG_DEBUG_SLAB
#define	DEBUG		1
#define	STATS		1
#define	FORCED_DEBUG	1
#else
#define	DEBUG		0
#define	STATS		0
#define	FORCED_DEBUG	0
#endif

/*
 * Parameters for xmem_cache_reap
 */
#define REAP_SCANLEN	10
#define REAP_PERFECT	10

/* Shouldn't this be in a header file somewhere? */
#define	BYTES_PER_WORD		sizeof(void *)

/* Legal flag mask for xmem_cache_create(). */
#if DEBUG
#define CREATE_MASK	(SLAB_DEBUG_INITIAL | SLAB_RED_ZONE | \
			 SLAB_POISON | SLAB_HWCACHE_ALIGN | \
			 SLAB_NO_REAP)
#else
#define CREATE_MASK	(SLAB_HWCACHE_ALIGN | SLAB_NO_REAP)
#endif

/*
 * xmem_bufctl_t:
 *
 * Bufctl's are used for linking objs within a slab
 * linked offsets.
 *
 * This implementaion relies on "struct page" for locating the cache &
 * slab an object belongs to.
 * This allows the bufctl structure to be small (one int), but limits
 * the number of objects a slab (not a cache) can contain when off-slab
 * bufctls are used. The limit is the size of the largest general cache
 * that does not use off-slab slabs.
 * For 32bit archs with 4 kB pages, is this 56.
 * This is not serious, as it is only for large objects, when it is unwise
 * to have too many per slab.
 * Note: This limit can be raised by introducing a general cache whose size
 * is less than 512 (PAGE_SIZE<<3), but greater than 256.
 */

#define BUFCTL_END	(((xmem_bufctl_t)(~0U))-0)
#define BUFCTL_FREE	(((xmem_bufctl_t)(~0U))-1)
#define	SLAB_LIMIT	(((xmem_bufctl_t)(~0U))-2)

/* Max number of objs-per-slab for caches which use off-slab slabs.
 * Needed to avoid a possible looping condition in xmem_cache_grow().
 */
static unsigned long offslab_limit;

/*
 * slab_t
 *
 * Manages the objs in a slab. Placed either at the beginning of mem allocated
 * for a slab, or allocated from an general cache.
 * Slabs are chained into three list: fully used, partial, fully free slabs.
 */
typedef struct slab_s {
    struct list_head list;
    unsigned long    colouroff;
    void            *s_mem;    /* including colour offset */
    unsigned int     inuse;    /* num of objs active in slab */
    xmem_bufctl_t    free;
} slab_t;

#define slab_bufctl(slabp) \
	((xmem_bufctl_t *)(((slab_t*)slabp)+1))

/*
 * cpucache_t
 *
 * Per cpu structures
 * The limit is stored in the per-cpu structure to reduce the data cache
 * footprint.
 */
typedef struct cpucache_s {
    unsigned int avail;
    unsigned int limit;
} cpucache_t;

#define cc_entry(cpucache) \
	((void **)(((cpucache_t*)(cpucache))+1))
#define cc_data(cachep) \
	((cachep)->cpudata[smp_processor_id()])
/*
 * xmem_cache_t
 *
 * manages a cache.
 */

#define CACHE_NAMELEN	20	/* max name length for a slab cache */

struct xmem_cache_s {
/* 1) each alloc & free */
    /* full, partial first, then free */
    struct list_head	slabs_full;
    struct list_head	slabs_partial;
    struct list_head	slabs_free;
    unsigned int		objsize;
    unsigned int	 	flags;	/* constant flags */
    unsigned int		num;	/* # of objs per slab */
    spinlock_t		spinlock;
#ifdef CONFIG_SMP
    unsigned int		batchcount;
#endif

/* 2) slab additions /removals */
    /* order of pgs per slab (2^n) */
    unsigned int		gfporder;
    size_t			colour;		/* cache colouring range */
    unsigned int		colour_off;	/* colour offset */
    unsigned int		colour_next;	/* cache colouring */
    xmem_cache_t		*slabp_cache;
    unsigned int		growing;
    unsigned int		dflags;		/* dynamic flags */

    /* constructor func */
    void (*ctor)(void *, xmem_cache_t *, unsigned long);

    /* de-constructor func */
    void (*dtor)(void *, xmem_cache_t *, unsigned long);

    unsigned long		failures;

/* 3) cache creation/removal */
    char			name[CACHE_NAMELEN];
    struct list_head	next;
#ifdef CONFIG_SMP
/* 4) per-cpu data */
    cpucache_t		*cpudata[NR_CPUS];
#endif
#if STATS
    unsigned long		num_active;
    unsigned long		num_allocations;
    unsigned long		high_mark;
    unsigned long		grown;
    unsigned long		reaped;
    unsigned long 		errors;
#ifdef CONFIG_SMP
    atomic_t		allochit;
    atomic_t		allocmiss;
    atomic_t		freehit;
    atomic_t		freemiss;
#endif
#endif
};

/* internal c_flags */
#define	CFLGS_OFF_SLAB	0x010000UL	/* slab management in own cache */
#define	CFLGS_OPTIMIZE	0x020000UL	/* optimized slab lookup */

/* c_dflags (dynamic flags). Need to hold the spinlock to access this member */
#define	DFLGS_GROWN	0x000001UL	/* don't reap a recently grown */

#define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)
#define	OPTIMIZE(x)	((x)->flags & CFLGS_OPTIMIZE)
#define	GROWN(x)	((x)->dlags & DFLGS_GROWN)

#if STATS
#define	STATS_INC_ACTIVE(x)	((x)->num_active++)
#define	STATS_DEC_ACTIVE(x)	((x)->num_active--)
#define	STATS_INC_ALLOCED(x)	((x)->num_allocations++)
#define	STATS_INC_GROWN(x)	((x)->grown++)
#define	STATS_INC_REAPED(x)	((x)->reaped++)
#define	STATS_SET_HIGH(x)	do { if ((x)->num_active > (x)->high_mark) \
					(x)->high_mark = (x)->num_active; \
				} while (0)
#define	STATS_INC_ERR(x)	((x)->errors++)
#else
#define	STATS_INC_ACTIVE(x)	do { } while (0)
#define	STATS_DEC_ACTIVE(x)	do { } while (0)
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_INC_GROWN(x)	do { } while (0)
#define	STATS_INC_REAPED(x)	do { } while (0)
#define	STATS_SET_HIGH(x)	do { } while (0)
#define	STATS_INC_ERR(x)	do { } while (0)
#endif

#if STATS && defined(CONFIG_SMP)
#define STATS_INC_ALLOCHIT(x)	atomic_inc(&(x)->allochit)
#define STATS_INC_ALLOCMISS(x)	atomic_inc(&(x)->allocmiss)
#define STATS_INC_FREEHIT(x)	atomic_inc(&(x)->freehit)
#define STATS_INC_FREEMISS(x)	atomic_inc(&(x)->freemiss)
#else
#define STATS_INC_ALLOCHIT(x)	do { } while (0)
#define STATS_INC_ALLOCMISS(x)	do { } while (0)
#define STATS_INC_FREEHIT(x)	do { } while (0)
#define STATS_INC_FREEMISS(x)	do { } while (0)
#endif

#if DEBUG
/* Magic nums for obj red zoning.
 * Placed in the first word before and the first word after an obj.
 */
#define	RED_MAGIC1	0x5A2CF071UL	/* when obj is active */
#define	RED_MAGIC2	0x170FC2A5UL	/* when obj is inactive */

/* ...and for poisoning */
#define	POISON_BYTE	0x5a		/* byte value for poisoning */
#define	POISON_END	0xa5		/* end-byte of poisoning */

#endif

/* maximum size of an obj (in 2^order pages) */
#define	MAX_OBJ_ORDER	5	/* 32 pages */

/*
 * Do not go above this order unless 0 objects fit into the slab.
 */
#define	BREAK_GFP_ORDER_HI	2
#define	BREAK_GFP_ORDER_LO	1
static int slab_break_gfp_order = BREAK_GFP_ORDER_LO;

/*
 * Absolute limit for the gfp order
 */
#define	MAX_GFP_ORDER	5	/* 32 pages */


/* Macros for storing/retrieving the cachep and or slab from the
 * global 'mem_map'. These are used to find the slab an obj belongs to.
 * With xfree(), these are used to find the cache which an obj belongs to.
 */
#define	SET_PAGE_CACHE(pg,x)  ((pg)->list.next = (struct list_head *)(x))
#define	GET_PAGE_CACHE(pg)    ((xmem_cache_t *)(pg)->list.next)
#define	SET_PAGE_SLAB(pg,x)   ((pg)->list.prev = (struct list_head *)(x))
#define	GET_PAGE_SLAB(pg)     ((slab_t *)(pg)->list.prev)

/* Size description struct for general caches. */
typedef struct cache_sizes {
    size_t		 cs_size;
    xmem_cache_t	*cs_cachep;
} cache_sizes_t;

static cache_sizes_t cache_sizes[] = {
    {    32,	NULL},
    {    64,	NULL},
    {   128,	NULL},
    {   256,	NULL},
    {   512,	NULL},
    {  1024,	NULL},
    {  2048,	NULL},
    {  4096,	NULL},
    {  8192,	NULL},
    { 16384,	NULL},
    { 32768,	NULL},
    { 65536,	NULL},
    {     0,	NULL}
};

/* internal cache of cache description objs */
static xmem_cache_t cache_cache = {
    slabs_full:    LIST_HEAD_INIT(cache_cache.slabs_full),
    slabs_partial: LIST_HEAD_INIT(cache_cache.slabs_partial),
    slabs_free:    LIST_HEAD_INIT(cache_cache.slabs_free),
    objsize:       sizeof(xmem_cache_t),
    flags:         SLAB_NO_REAP,
    spinlock:      SPIN_LOCK_UNLOCKED,
    colour_off:    L1_CACHE_BYTES,
    name:          "xmem_cache"
};

/* Guard access to the cache-chain. */
/* KAF: No semaphores, as we'll never wait around for I/O. */
static spinlock_t cache_chain_sem;
#define init_MUTEX(_m)   spin_lock_init(_m)
#define down(_m)         spin_lock_irqsave(_m,spin_flags)
#define up(_m)           spin_unlock_irqrestore(_m,spin_flags)

/* Place maintainer for reaping. */
static xmem_cache_t *clock_searchp = &cache_cache;

#define cache_chain (cache_cache.next)

#ifdef CONFIG_SMP
/*
 * chicken and egg problem: delay the per-cpu array allocation
 * until the general caches are up.
 */
static int g_cpucache_up;

static void enable_cpucache (xmem_cache_t *cachep);
static void enable_all_cpucaches (void);
#endif

/* Cal the num objs, wastage, and bytes left over for a given slab size. */
static void xmem_cache_estimate (unsigned long gfporder, size_t size,
                                 int flags, size_t *left_over, unsigned int *num)
{
    int i;
    size_t wastage = PAGE_SIZE<<gfporder;
    size_t extra = 0;
    size_t base = 0;

    if (!(flags & CFLGS_OFF_SLAB)) {
        base = sizeof(slab_t);
        extra = sizeof(xmem_bufctl_t);
    }
    i = 0;
    while (i*size + L1_CACHE_ALIGN(base+i*extra) <= wastage)
        i++;
    if (i > 0)
        i--;

    if (i > SLAB_LIMIT)
        i = SLAB_LIMIT;

    *num = i;
    wastage -= i*size;
    wastage -= L1_CACHE_ALIGN(base+i*extra);
    *left_over = wastage;
}

/* Initialisation - setup the `cache' cache. */
void __init xmem_cache_init(void)
{
    size_t left_over;

    init_MUTEX(&cache_chain_sem);
    INIT_LIST_HEAD(&cache_chain);

    xmem_cache_estimate(0, cache_cache.objsize, 0,
			&left_over, &cache_cache.num);
    if (!cache_cache.num)
        BUG();

    cache_cache.colour = left_over/cache_cache.colour_off;
    cache_cache.colour_next = 0;
}


/* Initialisation - setup remaining internal and general caches.
 * Called after the gfp() functions have been enabled, and before smp_init().
 */
void __init xmem_cache_sizes_init(unsigned long num_physpages)
{
    cache_sizes_t *sizes = cache_sizes;
    char name[20];
    /*
     * Fragmentation resistance on low memory - only use bigger
     * page orders on machines with more than 32MB of memory.
     */
    if (num_physpages > (32 << 20) >> PAGE_SHIFT)
        slab_break_gfp_order = BREAK_GFP_ORDER_HI;
    do {
        /* For performance, all the general caches are L1 aligned.
         * This should be particularly beneficial on SMP boxes, as it
         * eliminates "false sharing".
         * Note for systems short on memory removing the alignment will
         * allow tighter packing of the smaller caches. */
        sprintf(name,"size-%Zd",sizes->cs_size);
        if (!(sizes->cs_cachep =
              xmem_cache_create(name, sizes->cs_size,
                                0, SLAB_HWCACHE_ALIGN, NULL, NULL))) {
            BUG();
        }

        /* Inc off-slab bufctl limit until the ceiling is hit. */
        if (!(OFF_SLAB(sizes->cs_cachep))) {
            offslab_limit = sizes->cs_size-sizeof(slab_t);
            offslab_limit /= 2;
        }
        sizes++;
    } while (sizes->cs_size);
}

int __init xmem_cpucache_init(void)
{
#ifdef CONFIG_SMP
    g_cpucache_up = 1;
    enable_all_cpucaches();
#endif
    return 0;
}

/*__initcall(xmem_cpucache_init);*/

/* Interface to system's page allocator. No need to hold the cache-lock.
 */
static inline void *xmem_getpages(xmem_cache_t *cachep)
{
    void *addr;

    addr = (void*) alloc_xenheap_pages(cachep->gfporder);
    /* Assume that now we have the pages no one else can legally
     * messes with the 'struct page's.
     * However vm_scan() might try to test the structure to see if
     * it is a named-page or buffer-page.  The members it tests are
     * of no interest here.....
     */
    return addr;
}

/* Interface to system's page release. */
static inline void xmem_freepages (xmem_cache_t *cachep, void *addr)
{
    unsigned long i = (1<<cachep->gfporder);
    struct pfn_info *page = virt_to_page(addr);

    /* free_xenheap_pages() does not clear the type bit - we do that.
     * The pages have been unlinked from their cache-slab,
     * but their 'struct page's might be accessed in
     * vm_scan(). Shouldn't be a worry.
     */
    while (i--) {
        PageClearSlab(page);
        page++;
    }

    free_xenheap_pages((unsigned long)addr, cachep->gfporder);
}

#if DEBUG
static inline void xmem_poison_obj (xmem_cache_t *cachep, void *addr)
{
    int size = cachep->objsize;
    if (cachep->flags & SLAB_RED_ZONE) {
        addr += BYTES_PER_WORD;
        size -= 2*BYTES_PER_WORD;
    }
    memset(addr, POISON_BYTE, size);
    *(unsigned char *)(addr+size-1) = POISON_END;
}

static inline int xmem_check_poison_obj (xmem_cache_t *cachep, void *addr)
{
    int size = cachep->objsize;
    void *end;
    if (cachep->flags & SLAB_RED_ZONE) {
        addr += BYTES_PER_WORD;
        size -= 2*BYTES_PER_WORD;
    }
    end = memchr(addr, POISON_END, size);
    if (end != (addr+size-1))
        return 1;
    return 0;
}
#endif

/* Destroy all the objs in a slab, and release the mem back to the system.
 * Before calling the slab must have been unlinked from the cache.
 * The cache-lock is not held/needed.
 */
static void xmem_slab_destroy (xmem_cache_t *cachep, slab_t *slabp)
{
    if (cachep->dtor
#if DEBUG
        || cachep->flags & (SLAB_POISON | SLAB_RED_ZONE)
#endif
	) {
        int i;
        for (i = 0; i < cachep->num; i++) {
            void* objp = slabp->s_mem+cachep->objsize*i;
#if DEBUG
            if (cachep->flags & SLAB_RED_ZONE) {
                if (*((unsigned long*)(objp)) != RED_MAGIC1)
                    BUG();
                if (*((unsigned long*)(objp + cachep->objsize
                                       -BYTES_PER_WORD)) != RED_MAGIC1)
                    BUG();
                objp += BYTES_PER_WORD;
            }
#endif
            if (cachep->dtor)
                (cachep->dtor)(objp, cachep, 0);
#if DEBUG
            if (cachep->flags & SLAB_RED_ZONE) {
                objp -= BYTES_PER_WORD;
            }	
            if ((cachep->flags & SLAB_POISON)  &&
                xmem_check_poison_obj(cachep, objp))
                BUG();
#endif
        }
    }

    xmem_freepages(cachep, slabp->s_mem-slabp->colouroff);
    if (OFF_SLAB(cachep))
        xmem_cache_free(cachep->slabp_cache, slabp);
}

/**
 * xmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @offset: The offset to use within the page.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 * @dtor: A destructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a int, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache
 * and the @dtor is run before the pages are handed back.
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_NO_REAP - Don't automatically reap this cache when we're under
 * memory pressure.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */
xmem_cache_t *
xmem_cache_create (const char *name, size_t size, size_t offset,
                   unsigned long flags,
                   void (*ctor)(void*, xmem_cache_t *, unsigned long),
                   void (*dtor)(void*, xmem_cache_t *, unsigned long))
{
    const char *func_nm = KERN_ERR "xmem_create: ";
    size_t left_over, align, slab_size;
    xmem_cache_t *cachep = NULL;
    unsigned long spin_flags;

    /*
     * Sanity checks... these are all serious usage bugs.
     */
    if ((!name) ||
        ((strlen(name) >= CACHE_NAMELEN - 1)) ||
        (size < BYTES_PER_WORD) ||
        (size > (1<<MAX_OBJ_ORDER)*PAGE_SIZE) ||
        (dtor && !ctor) ||
        (offset < 0 || offset > size))
        BUG();

#if DEBUG
    if ((flags & SLAB_DEBUG_INITIAL) && !ctor) {
        /* No constructor, but inital state check requested */
        printk("%sNo con, but init state check requested - %s\n",
               func_nm, name);
        flags &= ~SLAB_DEBUG_INITIAL;
    }

    if ((flags & SLAB_POISON) && ctor) {
        /* request for poisoning, but we can't do that with a constructor */
        printk("%sPoisoning requested, but con given - %s\n",
               func_nm, name);
        flags &= ~SLAB_POISON;
    }
#if FORCED_DEBUG
    if (size < (PAGE_SIZE>>3))
        /*
         * do not red zone large object, causes severe
         * fragmentation.
         */
        flags |= SLAB_RED_ZONE;
    if (!ctor)
        flags |= SLAB_POISON;
#endif
#endif

    /*
     * Always checks flags, a caller might be expecting debug
     * support which isn't available.
     */
    if (flags & ~CREATE_MASK)
        BUG();

    /* Get cache's description obj. */
    cachep = (xmem_cache_t *)xmem_cache_alloc(&cache_cache);
    if (!cachep)
        goto opps;
    memset(cachep, 0, sizeof(xmem_cache_t));

    /* Check that size is in terms of words.  This is needed to avoid
     * unaligned accesses for some archs when redzoning is used, and makes
     * sure any on-slab bufctl's are also correctly aligned.
     */
    if (size & (BYTES_PER_WORD-1)) {
        size += (BYTES_PER_WORD-1);
        size &= ~(BYTES_PER_WORD-1);
        printk("%sForcing size word alignment - %s\n", func_nm, name);
    }
	
#if DEBUG
    if (flags & SLAB_RED_ZONE) {
        /*
         * There is no point trying to honour cache alignment
         * when redzoning.
         */
        flags &= ~SLAB_HWCACHE_ALIGN;
        size += 2*BYTES_PER_WORD;	/* words for redzone */
    }
#endif
    align = BYTES_PER_WORD;
    if (flags & SLAB_HWCACHE_ALIGN)
        align = L1_CACHE_BYTES;

    /* Determine if the slab management is 'on' or 'off' slab. */
    if (size >= (PAGE_SIZE>>3))
        /*
         * Size is large, assume best to place the slab management obj
         * off-slab (should allow better packing of objs).
         */
        flags |= CFLGS_OFF_SLAB;

    if (flags & SLAB_HWCACHE_ALIGN) {
        /* Need to adjust size so that objs are cache aligned. */
        /* Small obj size, can get at least two per cache line. */
        /* FIXME: only power of 2 supported, was better */
        while (size < align/2)
            align /= 2;
        size = (size+align-1)&(~(align-1));
    }

    /* Cal size (in pages) of slabs, and the num of objs per slab.
     * This could be made much more intelligent.  For now, try to avoid
     * using high page-orders for slabs.  When the gfp() funcs are more
     * friendly towards high-order requests, this should be changed.
     */
    do {
        unsigned int break_flag = 0;
    cal_wastage:
        xmem_cache_estimate(cachep->gfporder, size, flags,
                            &left_over, &cachep->num);
        if (break_flag)
            break;
        if (cachep->gfporder >= MAX_GFP_ORDER)
            break;
        if (!cachep->num)
            goto next;
        if (flags & CFLGS_OFF_SLAB && cachep->num > offslab_limit) {
            /* Oops, this num of objs will cause problems. */
            cachep->gfporder--;
            break_flag++;
            goto cal_wastage;
        }

        /*
         * Large num of objs is good, but v. large slabs are currently
         * bad for the gfp()s.
         */
        if (cachep->gfporder >= slab_break_gfp_order)
            break;

        if ((left_over*8) <= (PAGE_SIZE<<cachep->gfporder))
            break;	/* Acceptable internal fragmentation. */
    next:
        cachep->gfporder++;
    } while (1);

    if (!cachep->num) {
        printk("xmem_cache_create: couldn't create cache %s.\n", name);
        xmem_cache_free(&cache_cache, cachep);
        cachep = NULL;
        goto opps;
    }
    slab_size = L1_CACHE_ALIGN(cachep->num*sizeof(xmem_bufctl_t) + 
                               sizeof(slab_t));

    /*
     * If the slab has been placed off-slab, and we have enough space then
     * move it on-slab. This is at the expense of any extra colouring.
     */
    if (flags & CFLGS_OFF_SLAB && left_over >= slab_size) {
        flags &= ~CFLGS_OFF_SLAB;
        left_over -= slab_size;
    }

    /* Offset must be a multiple of the alignment. */
    offset += (align-1);
    offset &= ~(align-1);
    if (!offset)
        offset = L1_CACHE_BYTES;
    cachep->colour_off = offset;
    cachep->colour = left_over/offset;

    /* init remaining fields */
    if (!cachep->gfporder && !(flags & CFLGS_OFF_SLAB))
        flags |= CFLGS_OPTIMIZE;

    cachep->flags = flags;
    spin_lock_init(&cachep->spinlock);
    cachep->objsize = size;
    INIT_LIST_HEAD(&cachep->slabs_full);
    INIT_LIST_HEAD(&cachep->slabs_partial);
    INIT_LIST_HEAD(&cachep->slabs_free);

    if (flags & CFLGS_OFF_SLAB)
        cachep->slabp_cache = xmem_find_general_cachep(slab_size);
    cachep->ctor = ctor;
    cachep->dtor = dtor;
    /* Copy name over so we don't have problems with unloaded modules */
    strcpy(cachep->name, name);

#ifdef CONFIG_SMP
    if (g_cpucache_up)
        enable_cpucache(cachep);
#endif
    /* Need the semaphore to access the chain. */
    down(&cache_chain_sem);
    {
	xmem_cache_t *pc;

        list_for_each_entry(pc, &cache_chain, next) {
            /* The name field is constant - no lock needed. */
            if (!strcmp(pc->name, name))
                BUG();
        }
    }

    /* There is no reason to lock our new cache before we
     * link it in - no one knows about it yet...
     */
    list_add(&cachep->next, &cache_chain);
    up(&cache_chain_sem);
 opps:
    return cachep;
}


#if DEBUG
/*
 * This check if the xmem_cache_t pointer is chained in the cache_cache
 * list. -arca
 */
static int is_chained_xmem_cache(xmem_cache_t * cachep)
{
    xmem_cache_t *pc;
    int ret = 0;
    unsigned long spin_flags;

    /* Find the cache in the chain of caches. */
    down(&cache_chain_sem);
    list_for_each_entry(pc, &cache_chain, next) {
        if (pc == &cachep) {
            ret = 1;
            break;
        }
    }
    up(&cache_chain_sem);

    return ret;
}
#else
#define is_chained_xmem_cache(x) 1
#endif

#ifdef CONFIG_SMP
/*
 * Waits for all CPUs to execute func().
 */
static void smp_call_function_all_cpus(void (*func) (void *arg), void *arg)
{
    local_irq_disable();
    func(arg);
    local_irq_enable();

    if (smp_call_function(func, arg, 1, 1))
        BUG();
}
typedef struct ccupdate_struct_s
{
    xmem_cache_t *cachep;
    cpucache_t *new[NR_CPUS];
} ccupdate_struct_t;

static void do_ccupdate_local(void *info)
{
    ccupdate_struct_t *new = (ccupdate_struct_t *)info;
    cpucache_t *old = cc_data(new->cachep);
	
    cc_data(new->cachep) = new->new[smp_processor_id()];
    new->new[smp_processor_id()] = old;
}

static void free_block (xmem_cache_t* cachep, void** objpp, int len);

static void drain_cpu_caches(xmem_cache_t *cachep)
{
    ccupdate_struct_t new;
    int i;
    unsigned long spin_flags;

    memset(&new.new,0,sizeof(new.new));

    new.cachep = cachep;

    down(&cache_chain_sem);
    smp_call_function_all_cpus(do_ccupdate_local, (void *)&new);

    for (i = 0; i < smp_num_cpus; i++) {
        cpucache_t* ccold = new.new[cpu_logical_map(i)];
        if (!ccold || (ccold->avail == 0))
            continue;
        local_irq_disable();
        free_block(cachep, cc_entry(ccold), ccold->avail);
        local_irq_enable();
        ccold->avail = 0;
    }
    smp_call_function_all_cpus(do_ccupdate_local, (void *)&new);
    up(&cache_chain_sem);
}

#else
#define drain_cpu_caches(cachep)	do { } while (0)
#endif

static int __xmem_cache_shrink(xmem_cache_t *cachep)
{
    slab_t *slabp;
    int ret;

    drain_cpu_caches(cachep);

    spin_lock_irq(&cachep->spinlock);

    /* If the cache is growing, stop shrinking. */
    while (!cachep->growing) {
        struct list_head *p;

        p = cachep->slabs_free.prev;
        if (p == &cachep->slabs_free)
            break;

        slabp = list_entry(cachep->slabs_free.prev, slab_t, list);
#if DEBUG
        if (slabp->inuse)
            BUG();
#endif
        list_del(&slabp->list);

        spin_unlock_irq(&cachep->spinlock);
        xmem_slab_destroy(cachep, slabp);
        spin_lock_irq(&cachep->spinlock);
    }
    ret = (!list_empty(&cachep->slabs_full) || 
           !list_empty(&cachep->slabs_partial));
    spin_unlock_irq(&cachep->spinlock);
    return ret;
}

/**
 * xmem_cache_shrink - Shrink a cache.
 * @cachep: The cache to shrink.
 *
 * Releases as many slabs as possible for a cache.
 * To help debugging, a zero exit status indicates all slabs were released.
 */
int xmem_cache_shrink(xmem_cache_t *cachep)
{
    if (!cachep || !is_chained_xmem_cache(cachep))
        BUG();

    return __xmem_cache_shrink(cachep);
}

/**
 * xmem_cache_destroy - delete a cache
 * @cachep: the cache to destroy
 *
 * Remove a xmem_cache_t object from the slab cache.
 * Returns 0 on success.
 *
 * It is expected this function will be called by a module when it is
 * unloaded.  This will remove the cache completely, and avoid a duplicate
 * cache being allocated each time a module is loaded and unloaded, if the
 * module doesn't have persistent in-kernel storage across loads and unloads.
 *
 * The caller must guarantee that noone will allocate memory from the cache
 * during the xmem_cache_destroy().
 */
int xmem_cache_destroy (xmem_cache_t * cachep)
{
    unsigned long spin_flags;

    if (!cachep || cachep->growing)
        BUG();

    /* Find the cache in the chain of caches. */
    down(&cache_chain_sem);
    /* the chain is never empty, cache_cache is never destroyed */
    if (clock_searchp == cachep)
        clock_searchp = list_entry(cachep->next.next,
                                   xmem_cache_t, next);
    list_del(&cachep->next);
    up(&cache_chain_sem);

    if (__xmem_cache_shrink(cachep)) {
        printk(KERN_ERR "xmem_cache_destroy: Can't free all objects %p\n",
               cachep);
        down(&cache_chain_sem);
        list_add(&cachep->next,&cache_chain);
        up(&cache_chain_sem);
        return 1;
    }
#ifdef CONFIG_SMP
    {
        int i;
        for (i = 0; i < NR_CPUS; i++)
            xfree(cachep->cpudata[i]);
    }
#endif
    xmem_cache_free(&cache_cache, cachep);

    return 0;
}

/* Get the memory for a slab management obj. */
static inline slab_t *xmem_cache_slabmgmt(xmem_cache_t *cachep,
                                          void *objp, int colour_off, 
                                          int local_flags)
{
    slab_t *slabp;
	
    if (OFF_SLAB(cachep)) {
        /* Slab management obj is off-slab. */
        slabp = xmem_cache_alloc(cachep->slabp_cache);
        if (!slabp)
            return NULL;
    } else {
        /* FIXME: change to
           slabp = objp
           * if you enable OPTIMIZE
           */
        slabp = objp+colour_off;
        colour_off += L1_CACHE_ALIGN(cachep->num *
                                     sizeof(xmem_bufctl_t) + sizeof(slab_t));
    }
    slabp->inuse = 0;
    slabp->colouroff = colour_off;
    slabp->s_mem = objp+colour_off;

    return slabp;
}

static inline void xmem_cache_init_objs(xmem_cache_t *cachep,
                                         slab_t *slabp,
                                        unsigned long ctor_flags)
{
    int i;

    for (i = 0; i < cachep->num; i++) {
        void* objp = slabp->s_mem+cachep->objsize*i;
#if DEBUG
        if (cachep->flags & SLAB_RED_ZONE) {
            *((unsigned long*)(objp)) = RED_MAGIC1;
            *((unsigned long*)(objp + cachep->objsize -
                               BYTES_PER_WORD)) = RED_MAGIC1;
            objp += BYTES_PER_WORD;
        }
#endif

        /*
         * Constructors are not allowed to allocate memory from
         * the same cache which they are a constructor for.
         * Otherwise, deadlock. They must also be threaded.
         */
        if (cachep->ctor)
            cachep->ctor(objp, cachep, ctor_flags);
#if DEBUG
        if (cachep->flags & SLAB_RED_ZONE)
            objp -= BYTES_PER_WORD;
        if (cachep->flags & SLAB_POISON)
            /* need to poison the objs */
            xmem_poison_obj(cachep, objp);
        if (cachep->flags & SLAB_RED_ZONE) {
            if (*((unsigned long*)(objp)) != RED_MAGIC1)
                BUG();
            if (*((unsigned long*)(objp + cachep->objsize -
                                   BYTES_PER_WORD)) != RED_MAGIC1)
                BUG();
        }
#endif
        slab_bufctl(slabp)[i] = i+1;
    }
    slab_bufctl(slabp)[i-1] = BUFCTL_END;
    slabp->free = 0;
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * xmem_cache_alloc() when there are no active objs left in a cache.
 */
static int xmem_cache_grow(xmem_cache_t * cachep)
{
    slab_t	*slabp;
    struct pfn_info	*page; unsigned int i;
    void		*objp;
    size_t		 offset;
    unsigned long	 ctor_flags;
    unsigned long	 save_flags;

    ctor_flags = SLAB_CTOR_CONSTRUCTOR;

    /* About to mess with non-constant members - lock. */
    spin_lock_irqsave(&cachep->spinlock, save_flags);

    /* Get colour for the slab, and cal the next value. */
    offset = cachep->colour_next;
    cachep->colour_next++;
    if (cachep->colour_next >= cachep->colour)
        cachep->colour_next = 0;
    offset *= cachep->colour_off;
    cachep->dflags |= DFLGS_GROWN;

    cachep->growing++;
    spin_unlock_irqrestore(&cachep->spinlock, save_flags);

    /* A series of memory allocations for a new slab.
     * Neither the cache-chain semaphore, or cache-lock, are
     * held, but the incrementing c_growing prevents this
     * cache from being reaped or shrunk.
     * Note: The cache could be selected in for reaping in
     * xmem_cache_reap(), but when the final test is made the
     * growing value will be seen.
     */

    /* Get mem for the objs. */
    if (!(objp = xmem_getpages(cachep)))
        goto failed;

    /* Get slab management. */
    if (!(slabp = xmem_cache_slabmgmt(cachep, objp, offset, 0)))
        goto opps1;

    /* Nasty!!!!!! I hope this is OK. */
    i = 1 << cachep->gfporder;
    page = virt_to_page(objp);
    do {
        SET_PAGE_CACHE(page, cachep);
        SET_PAGE_SLAB(page, slabp);
        PageSetSlab(page);
        page++;
    } while (--i);

    xmem_cache_init_objs(cachep, slabp, ctor_flags);

    spin_lock_irqsave(&cachep->spinlock, save_flags);
    cachep->growing--;

    /* Make slab active. */
    list_add_tail(&slabp->list, &cachep->slabs_free);
    STATS_INC_GROWN(cachep);
    cachep->failures = 0;

    spin_unlock_irqrestore(&cachep->spinlock, save_flags);
    return 1;
 opps1:
    xmem_freepages(cachep, objp);
 failed:
    spin_lock_irqsave(&cachep->spinlock, save_flags);
    cachep->growing--;
    spin_unlock_irqrestore(&cachep->spinlock, save_flags);
    return 0;
}

/*
 * Perform extra freeing checks:
 * - detect double free
 * - detect bad pointers.
 * Called with the cache-lock held.
 */

#if DEBUG
static int xmem_extra_free_checks (xmem_cache_t * cachep,
                                   slab_t *slabp, void * objp)
{
    int i;
    unsigned int objnr = (objp-slabp->s_mem)/cachep->objsize;

    if (objnr >= cachep->num)
        BUG();
    if (objp != slabp->s_mem + objnr*cachep->objsize)
        BUG();

    /* Check slab's freelist to see if this obj is there. */
    for (i = slabp->free; i != BUFCTL_END; i = slab_bufctl(slabp)[i]) {
        if (i == objnr)
            BUG();
    }
    return 0;
}
#endif

static inline void * xmem_cache_alloc_one_tail (xmem_cache_t *cachep,
						slab_t *slabp)
{
    void *objp;

    STATS_INC_ALLOCED(cachep);
    STATS_INC_ACTIVE(cachep);
    STATS_SET_HIGH(cachep);

    /* get obj pointer */
    slabp->inuse++;
    objp = slabp->s_mem + slabp->free*cachep->objsize;
    slabp->free=slab_bufctl(slabp)[slabp->free];

    if (unlikely(slabp->free == BUFCTL_END)) {
        list_del(&slabp->list);
        list_add(&slabp->list, &cachep->slabs_full);
    }
#if DEBUG
    if (cachep->flags & SLAB_POISON)
        if (xmem_check_poison_obj(cachep, objp))
            BUG();
    if (cachep->flags & SLAB_RED_ZONE) {
        /* Set alloc red-zone, and check old one. */
        if (xchg((unsigned long *)objp, RED_MAGIC2) !=
            RED_MAGIC1)
            BUG();
        if (xchg((unsigned long *)(objp+cachep->objsize -
                                   BYTES_PER_WORD), RED_MAGIC2) != RED_MAGIC1)
            BUG();
        objp += BYTES_PER_WORD;
    }
#endif
    return objp;
}

/*
 * Returns a ptr to an obj in the given cache.
 * caller must guarantee synchronization
 * #define for the goto optimization 8-)
 */
#define xmem_cache_alloc_one(cachep)				\
({								\
	struct list_head * slabs_partial, * entry;		\
	slab_t *slabp;						\
								\
	slabs_partial = &(cachep)->slabs_partial;		\
	entry = slabs_partial->next;				\
	if (unlikely(entry == slabs_partial)) {			\
		struct list_head * slabs_free;			\
		slabs_free = &(cachep)->slabs_free;		\
		entry = slabs_free->next;			\
		if (unlikely(entry == slabs_free))		\
			goto alloc_new_slab;			\
		list_del(entry);				\
		list_add(entry, slabs_partial);			\
	}							\
								\
	slabp = list_entry(entry, slab_t, list);		\
	xmem_cache_alloc_one_tail(cachep, slabp);		\
})

#ifdef CONFIG_SMP
void* xmem_cache_alloc_batch(xmem_cache_t* cachep)
{
    int batchcount = cachep->batchcount;
    cpucache_t* cc = cc_data(cachep);

    spin_lock(&cachep->spinlock);
    while (batchcount--) {
        struct list_head * slabs_partial, * entry;
        slab_t *slabp;
        /* Get slab alloc is to come from. */
        slabs_partial = &(cachep)->slabs_partial;
        entry = slabs_partial->next;
        if (unlikely(entry == slabs_partial)) {
            struct list_head * slabs_free;
            slabs_free = &(cachep)->slabs_free;
            entry = slabs_free->next;
            if (unlikely(entry == slabs_free))
                break;
            list_del(entry);
            list_add(entry, slabs_partial);
        }

        slabp = list_entry(entry, slab_t, list);
        cc_entry(cc)[cc->avail++] =
            xmem_cache_alloc_one_tail(cachep, slabp);
    }
    spin_unlock(&cachep->spinlock);

    if (cc->avail)
        return cc_entry(cc)[--cc->avail];
    return NULL;
}
#endif

static inline void *__xmem_cache_alloc(xmem_cache_t *cachep)
{
    unsigned long flags;
    void* objp;

 try_again:
    local_irq_save(flags);
#ifdef CONFIG_SMP
    {
        cpucache_t *cc = cc_data(cachep);

        if (cc) {
            if (cc->avail) {
                STATS_INC_ALLOCHIT(cachep);
                objp = cc_entry(cc)[--cc->avail];
            } else {
                STATS_INC_ALLOCMISS(cachep);
                objp = xmem_cache_alloc_batch(cachep);
                if (!objp)
                    goto alloc_new_slab_nolock;
            }
        } else {
            spin_lock(&cachep->spinlock);
            objp = xmem_cache_alloc_one(cachep);
            spin_unlock(&cachep->spinlock);
        }
    }
#else
    objp = xmem_cache_alloc_one(cachep);
#endif
    local_irq_restore(flags);
    return objp;
 alloc_new_slab:
#ifdef CONFIG_SMP
    spin_unlock(&cachep->spinlock);
 alloc_new_slab_nolock:
#endif
    local_irq_restore(flags);
    if (xmem_cache_grow(cachep))
        /* Someone may have stolen our objs.  Doesn't matter, we'll
         * just come back here again.
         */
        goto try_again;
    return NULL;
}

/*
 * Release an obj back to its cache. If the obj has a constructed
 * state, it should be in this state _before_ it is released.
 * - caller is responsible for the synchronization
 */

#if DEBUG
# define CHECK_NR(pg)						\
	do {							\
		if (!VALID_PAGE(pg)) {				\
			printk(KERN_ERR "xfree: out of range ptr %lxh.\n", \
				(unsigned long)objp);		\
			BUG();					\
		} \
	} while (0)
# define CHECK_PAGE(page)					\
	do {							\
		CHECK_NR(page);					\
		if (!PageSlab(page)) {				\
			printk(KERN_ERR "xfree: bad ptr %lxh.\n", \
				(unsigned long)objp);		\
			BUG();					\
		}						\
	} while (0)

#else
# define CHECK_PAGE(pg)	do { } while (0)
#endif

static inline void xmem_cache_free_one(xmem_cache_t *cachep, void *objp)
{
    slab_t* slabp;

    CHECK_PAGE(virt_to_page(objp));
    /* reduces memory footprint
     *
     if (OPTIMIZE(cachep))
     slabp = (void*)((unsigned long)objp&(~(PAGE_SIZE-1)));
     else
    */
    slabp = GET_PAGE_SLAB(virt_to_page(objp));

#if DEBUG
    if (cachep->flags & SLAB_DEBUG_INITIAL)
        /* Need to call the slab's constructor so the
         * caller can perform a verify of its state (debugging).
         * Called without the cache-lock held.
         */
        cachep->ctor(objp, cachep, SLAB_CTOR_CONSTRUCTOR|SLAB_CTOR_VERIFY);

    if (cachep->flags & SLAB_RED_ZONE) {
        objp -= BYTES_PER_WORD;
        if (xchg((unsigned long *)objp, RED_MAGIC1) != RED_MAGIC2)
            /* Either write before start, or a double free. */
            BUG();
        if (xchg((unsigned long *)(objp+cachep->objsize -
                                   BYTES_PER_WORD), RED_MAGIC1) != RED_MAGIC2)
            /* Either write past end, or a double free. */
            BUG();
    }
    if (cachep->flags & SLAB_POISON)
        xmem_poison_obj(cachep, objp);
    if (xmem_extra_free_checks(cachep, slabp, objp))
        return;
#endif
    {
        unsigned int objnr = (objp-slabp->s_mem)/cachep->objsize;

        slab_bufctl(slabp)[objnr] = slabp->free;
        slabp->free = objnr;
    }
    STATS_DEC_ACTIVE(cachep);
	
    /* fixup slab chains */
    {
        int inuse = slabp->inuse;
        if (unlikely(!--slabp->inuse)) {
            /* Was partial or full, now empty. */
            list_del(&slabp->list);
            list_add(&slabp->list, &cachep->slabs_free);
        } else if (unlikely(inuse == cachep->num)) {
            /* Was full. */
            list_del(&slabp->list);
            list_add(&slabp->list, &cachep->slabs_partial);
        }
    }
}

#ifdef CONFIG_SMP
static inline void __free_block (xmem_cache_t* cachep,
                                 void** objpp, int len)
{
    for ( ; len > 0; len--, objpp++)
        xmem_cache_free_one(cachep, *objpp);
}

static void free_block (xmem_cache_t* cachep, void** objpp, int len)
{
    spin_lock(&cachep->spinlock);
    __free_block(cachep, objpp, len);
    spin_unlock(&cachep->spinlock);
}
#endif

/*
 * __xmem_cache_free
 * called with disabled ints
 */
static inline void __xmem_cache_free (xmem_cache_t *cachep, void* objp)
{
#ifdef CONFIG_SMP
    cpucache_t *cc = cc_data(cachep);

    CHECK_PAGE(virt_to_page(objp));
    if (cc) {
        int batchcount;
        if (cc->avail < cc->limit) {
            STATS_INC_FREEHIT(cachep);
            cc_entry(cc)[cc->avail++] = objp;
            return;
        }
        STATS_INC_FREEMISS(cachep);
        batchcount = cachep->batchcount;
        cc->avail -= batchcount;
        free_block(cachep,
                   &cc_entry(cc)[cc->avail],batchcount);
        cc_entry(cc)[cc->avail++] = objp;
        return;
    } else {
        free_block(cachep, &objp, 1);
    }
#else
    xmem_cache_free_one(cachep, objp);
#endif
}

/**
 * xmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 *
 * Allocate an object from this cache.  The flags are only relevant
 * if the cache has no available objects.
 */
void *xmem_cache_alloc(xmem_cache_t *cachep)
{
    return __xmem_cache_alloc(cachep);
}

/**
 * _xmalloc - allocate memory
 * @size: how many bytes of memory are required.
 */
void *_xmalloc(size_t size)
{
    cache_sizes_t *csizep = cache_sizes;

    for (; csizep->cs_size; csizep++) {
        if (size > csizep->cs_size)
            continue;
        return __xmem_cache_alloc(csizep->cs_cachep);
    }
    return NULL;
}

/**
 * xmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void xmem_cache_free (xmem_cache_t *cachep, void *objp)
{
    unsigned long flags;
#if DEBUG
    CHECK_PAGE(virt_to_page(objp));
    if (cachep != GET_PAGE_CACHE(virt_to_page(objp)))
        BUG();
#endif

    local_irq_save(flags);
    __xmem_cache_free(cachep, objp);
    local_irq_restore(flags);
}

/**
 * xfree - free previously allocated memory
 * @objp: pointer returned by xmalloc.
 *
 * Don't free memory not originally allocated by xmalloc()
 * or you will run into trouble.
 */
void xfree (const void *objp)
{
    xmem_cache_t *c;
    unsigned long flags;

    if (!objp)
        return;
    local_irq_save(flags);
    CHECK_PAGE(virt_to_page(objp));
    c = GET_PAGE_CACHE(virt_to_page(objp));
    __xmem_cache_free(c, (void*)objp);
    local_irq_restore(flags);
}

xmem_cache_t *xmem_find_general_cachep(size_t size)
{
    cache_sizes_t *csizep = cache_sizes;

    /* This function could be moved to the header file, and
     * made inline so consumers can quickly determine what
     * cache pointer they require.
     */
    for ( ; csizep->cs_size; csizep++) {
        if (size > csizep->cs_size)
            continue;
        break;
    }
    return csizep->cs_cachep;
}

#ifdef CONFIG_SMP

/* called with cache_chain_sem acquired.  */
static int xmem_tune_cpucache (xmem_cache_t* cachep, int limit, int batchcount)
{
    ccupdate_struct_t new;
    int i;

    /*
     * These are admin-provided, so we are more graceful.
     */
    if (limit < 0)
        return -EINVAL;
    if (batchcount < 0)
        return -EINVAL;
    if (batchcount > limit)
        return -EINVAL;
    if (limit != 0 && !batchcount)
        return -EINVAL;

    memset(&new.new,0,sizeof(new.new));
    if (limit) {
        for (i = 0; i< smp_num_cpus; i++) {
            cpucache_t* ccnew;

            ccnew = _xmalloc(sizeof(void*)*limit+sizeof(cpucache_t));
            if (!ccnew)
                goto oom;
            ccnew->limit = limit;
            ccnew->avail = 0;
            new.new[cpu_logical_map(i)] = ccnew;
        }
    }
    new.cachep = cachep;
    spin_lock_irq(&cachep->spinlock);
    cachep->batchcount = batchcount;
    spin_unlock_irq(&cachep->spinlock);

    smp_call_function_all_cpus(do_ccupdate_local, (void *)&new);

    for (i = 0; i < smp_num_cpus; i++) {
        cpucache_t* ccold = new.new[cpu_logical_map(i)];
        if (!ccold)
            continue;
        local_irq_disable();
        free_block(cachep, cc_entry(ccold), ccold->avail);
        local_irq_enable();
        xfree(ccold);
    }
    return 0;
 oom:
    for (i--; i >= 0; i--)
        xfree(new.new[cpu_logical_map(i)]);
    return -ENOMEM;
}

static void enable_cpucache (xmem_cache_t *cachep)
{
    int err;
    int limit;

    /* FIXME: optimize */
    if (cachep->objsize > PAGE_SIZE)
        return;
    if (cachep->objsize > 1024)
        limit = 60;
    else if (cachep->objsize > 256)
        limit = 124;
    else
        limit = 252;

    err = xmem_tune_cpucache(cachep, limit, limit/2);
    if (err)
        printk(KERN_ERR "enable_cpucache failed for %s, error %d.\n",
               cachep->name, -err);
}

static void enable_all_cpucaches (void)
{
    struct list_head* p;
    unsigned long spin_flags;

    down(&cache_chain_sem);

    p = &cache_cache.next;
    do {
        xmem_cache_t* cachep = list_entry(p, xmem_cache_t, next);

        enable_cpucache(cachep);
        p = cachep->next.next;
    } while (p != &cache_cache.next);

    up(&cache_chain_sem);
}
#endif

/**
 * xmem_cache_reap - Reclaim memory from caches.
 */
int xmem_cache_reap(void)
{
    slab_t *slabp;
    xmem_cache_t *searchp;
    xmem_cache_t *best_cachep;
    unsigned int best_pages;
    unsigned int best_len;
    unsigned int scan;
    int ret = 0;
    unsigned long spin_flags;

    down(&cache_chain_sem);

    scan = REAP_SCANLEN;
    best_len = 0;
    best_pages = 0;
    best_cachep = NULL;
    searchp = clock_searchp;
    do {
        unsigned int pages;
        struct list_head* p;
        unsigned int full_free;

        /* It's safe to test this without holding the cache-lock. */
        if (searchp->flags & SLAB_NO_REAP)
            goto next;
        spin_lock_irq(&searchp->spinlock);
        if (searchp->growing)
            goto next_unlock;
        if (searchp->dflags & DFLGS_GROWN) {
            searchp->dflags &= ~DFLGS_GROWN;
            goto next_unlock;
        }
#ifdef CONFIG_SMP
        {
            cpucache_t *cc = cc_data(searchp);
            if (cc && cc->avail) {
                __free_block(searchp, cc_entry(cc), cc->avail);
                cc->avail = 0;
            }
        }
#endif

        full_free = 0;
        p = searchp->slabs_free.next;
        while (p != &searchp->slabs_free) {
            slabp = list_entry(p, slab_t, list);
#if DEBUG
            if (slabp->inuse)
                BUG();
#endif
            full_free++;
            p = p->next;
        }

        /*
         * Try to avoid slabs with constructors and/or
         * more than one page per slab (as it can be difficult
         * to get high orders from gfp()).
         */
        pages = full_free * (1<<searchp->gfporder);
        if (searchp->ctor)
            pages = (pages*4+1)/5;
        if (searchp->gfporder)
            pages = (pages*4+1)/5;
        if (pages > best_pages) {
            best_cachep = searchp;
            best_len = full_free;
            best_pages = pages;
            if (pages >= REAP_PERFECT) {
                clock_searchp = list_entry(searchp->next.next,
                                           xmem_cache_t,next);
                goto perfect;
            }
        }
    next_unlock:
        spin_unlock_irq(&searchp->spinlock);
    next:
        searchp = list_entry(searchp->next.next,xmem_cache_t,next);
    } while (--scan && searchp != clock_searchp);

    clock_searchp = searchp;

    if (!best_cachep)
        /* couldn't find anything to reap */
        goto out;

    spin_lock_irq(&best_cachep->spinlock);
 perfect:
    /* free only 50% of the free slabs */
    best_len = (best_len + 1)/2;
    for (scan = 0; scan < best_len; scan++) {
        struct list_head *p;

        if (best_cachep->growing)
            break;
        p = best_cachep->slabs_free.prev;
        if (p == &best_cachep->slabs_free)
            break;
        slabp = list_entry(p,slab_t,list);
#if DEBUG
        if (slabp->inuse)
            BUG();
#endif
        list_del(&slabp->list);
        STATS_INC_REAPED(best_cachep);

        /* Safe to drop the lock. The slab is no longer linked to the
         * cache.
         */
        spin_unlock_irq(&best_cachep->spinlock);
        xmem_slab_destroy(best_cachep, slabp);
        spin_lock_irq(&best_cachep->spinlock);
    }
    spin_unlock_irq(&best_cachep->spinlock);
    ret = scan * (1 << best_cachep->gfporder);
 out:
    up(&cache_chain_sem);
    return ret;
}

void dump_slabinfo()
{
    struct list_head *p;
    unsigned long spin_flags;

    /* Output format version, so at least we can change it without _too_
     * many complaints.
     */
    printk( "slabinfo - version: 1.1"
#if STATS
            " (statistics)"
#endif
#ifdef CONFIG_SMP
            " (SMP)"
#endif
            "\n");
    down(&cache_chain_sem);
    p = &cache_cache.next;
    do {
        xmem_cache_t	*cachep;
        slab_t		*slabp;
        unsigned long	active_objs;
        unsigned long	num_objs;
        unsigned long	active_slabs = 0;
        unsigned long	num_slabs;
        cachep = list_entry(p, xmem_cache_t, next);

        spin_lock_irq(&cachep->spinlock);
        active_objs = 0;
        num_slabs = 0;
        list_for_each_entry(slabp, &cachep->slabs_full, list) {
            if (slabp->inuse != cachep->num)
                BUG();
            active_objs += cachep->num;
            active_slabs++;
        }
        list_for_each_entry(slabp, &cachep->slabs_partial, list) {
            if (slabp->inuse == cachep->num || !slabp->inuse)
                BUG();
            active_objs += slabp->inuse;
            active_slabs++;
        }
        list_for_each_entry(slabp, &cachep->slabs_free, list) {
            if (slabp->inuse)
                BUG();
            num_slabs++;
        }
        num_slabs+=active_slabs;
        num_objs = num_slabs*cachep->num;

        printk("%-17s %6lu %6lu %6u %4lu %4lu %4u",
               cachep->name, active_objs, num_objs, cachep->objsize,
               active_slabs, num_slabs, (1<<cachep->gfporder));

#if STATS
        {
            unsigned long errors = cachep->errors;
            unsigned long high = cachep->high_mark;
            unsigned long grown = cachep->grown;
            unsigned long reaped = cachep->reaped;
            unsigned long allocs = cachep->num_allocations;

            printk(" : %6lu %7lu %5lu %4lu %4lu",
                   high, allocs, grown, reaped, errors);
        }
#endif
#ifdef CONFIG_SMP
        {
            unsigned int batchcount = cachep->batchcount;
            unsigned int limit;

            if (cc_data(cachep))
                limit = cc_data(cachep)->limit;
            else
                limit = 0;
            printk(" : %4u %4u",
                   limit, batchcount);
        }
#endif
#if STATS && defined(CONFIG_SMP)
        {
            unsigned long allochit = atomic_read(&cachep->allochit);
            unsigned long allocmiss = atomic_read(&cachep->allocmiss);
            unsigned long freehit = atomic_read(&cachep->freehit);
            unsigned long freemiss = atomic_read(&cachep->freemiss);
            printk(" : %6lu %6lu %6lu %6lu",
                   allochit, allocmiss, freehit, freemiss);
        }
#endif
        printk("\n");
        spin_unlock_irq(&cachep->spinlock);

        p = cachep->next.next;
    } while (p != &cache_cache.next);

    up(&cache_chain_sem);

    return;
}
