/******************************************************************************
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bidir-hash.h"

static const uint32_t hash_sizes[] = {53, 97, 193, 389, 769, 1543, 3079, 6151,
    12289, 24593, 49157, 98317, 196613, 393241, 786433, 1572869, 3145739,
    6291469, 12582917, 25165843, 50331653, 100663319, 201326611, 402653189,
    805306457, 1610612741};
static const uint16_t hash_sizes_len =
            sizeof(hash_sizes)/sizeof(hash_sizes[0]);
static const float hash_max_load_fact = 0.65;
static const float hash_min_load_fact = 0.10;

/* How many buckets will be covered by a single rw lock */
#define BUCKETS_PER_LOCK    64
#define nr_locks(_nr_buckets)   (1 + (_nr_buckets) / BUCKETS_PER_LOCK)


#define HASH_LOCK                                                              \
    pthread_rwlock_t hash_lock

#define BUCKET_LOCK                                                            \
    pthread_rwlock_t bucket_lock

struct hash_entry
{
    __k_t key;
    __v_t value;
    /* This structure will belong to two buckets, one in each hash table */
    struct hash_entry *key_next;
    struct hash_entry *value_next;
};

struct bucket
{
    struct hash_entry *hash_entry;
};

struct bucket_lock
{
    BUCKET_LOCK;
};

struct __hash
{
    int lock_alive;
    HASH_LOCK;                            /* protects:
                                           * *_tab, tab_size, size_idx, *_load
                                           * (all writes with wrlock)
                                           */
    uint32_t nr_ent;                      /* # entries held in hashtables */
    struct bucket *key_tab;               /* forward mapping hashtable    */
    struct bucket *value_tab;             /* backward mapping hashtable   */
    struct bucket_lock *key_lock_tab;     /* key table bucket locks       */
    struct bucket_lock *value_lock_tab;   /* value table bucket locks     */
    uint32_t tab_size;                    /* # buckets is hashtables      */
    uint16_t size_idx;                    /* table size index             */
    uint32_t max_load;                    /* # entries before rehash      */
    uint32_t min_load;                    /* # entries before rehash      */
};

struct __hash *__hash_init   (struct __hash *h, uint32_t min_size);
int            __key_lookup  (struct __hash *h, __k_t k, __v_t *vp);
int            __value_lookup(struct __hash *h, __v_t v, __k_t *kp);
int            __insert      (struct __hash *h, __k_t k, __v_t v);
int            __key_remove  (struct __hash *h, __k_t k, __v_t *vp);
int            __value_remove(struct __hash *h, __v_t v, __k_t *kp);
int            __hash_destroy(struct __hash *h,
                    void (*entry_consumer)(__k_t k, __v_t v, void *p),
                    void *d);
int            __hash_iterator(struct __hash *h,
                        int (*entry_consumer)(__k_t k, __v_t v, void *p),
                        void *d);
static void      hash_resize(struct __hash *h);

#if defined(__arm__)
static inline void atomic_inc(uint32_t *v)
{
        unsigned long tmp;
        int result;

        __asm__ __volatile__("@ atomic_inc\n"
"1:     ldrex   %0, [%3]\n"
"       add     %0, %0, #1\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (result), "=&r" (tmp), "+Qo" (*v)
        : "r" (v)
        : "cc");
}
static inline void atomic_dec(uint32_t *v)
{
        unsigned long tmp;
        int result;

        __asm__ __volatile__("@ atomic_dec\n"
"1:     ldrex   %0, [%3]\n"
"       sub     %0, %0, #1\n"
"       strex   %1, %0, [%3]\n"
"       teq     %1, #0\n"
"       bne     1b"
        : "=&r" (result), "=&r" (tmp), "+Qo" (*v)
        : "r" (v)
        : "cc");
}

#elif defined(__aarch64__)

static inline void atomic_inc(uint32_t *v)
{
        unsigned long tmp;
        int result;

        asm volatile("// atomic_inc\n"
"1:     ldxr    %w0, [%3]\n"
"       add     %w0, %w0, #1\n"
"       stxr    %w1, %w0, [%3]\n"
"       cbnz    %w1, 1b"
        : "=&r" (result), "=&r" (tmp), "+o" (v)
        : "r" (v)
        : "cc");
}

static inline void atomic_dec(uint32_t *v)
{
        unsigned long tmp;
        int result;

        asm volatile("// atomic_dec\n"
"1:     ldxr    %w0, [%3]\n"
"       sub     %w0, %w0, #1\n"
"       stxr    %w1, %w0, [%3]\n"
"       cbnz    %w1, 1b"
        : "=&r" (result), "=&r" (tmp), "+o" (v)
        : "r" (v)
        : "cc");
}

#else /* __x86__ */
static inline void atomic_inc(uint32_t *v)
{
    asm volatile (
        "lock ; incl %0"
        : "=m" (*(volatile uint32_t *)v)
        : "m" (*(volatile uint32_t *)v) );
}
static inline void atomic_dec(uint32_t *v)
{
    asm volatile (
        "lock ; decl %0"
        : "=m" (*(volatile uint32_t *)v)
        : "m" (*(volatile uint32_t *)v) );
}
#endif

#ifdef BIDIR_USE_STDMALLOC

static void* alloc_entry(struct __hash *h, int size)
{
    return malloc(size);
}

static void alloc_buckets(struct __hash *h,
                          int nr_buckets,
                          struct bucket **bucket_tab,
                          struct bucket_lock **bucket_locks_tab)
{
    *bucket_tab = (struct bucket*)
        malloc(nr_buckets * sizeof(struct bucket));
    *bucket_locks_tab = (struct bucket_lock*)
        malloc(nr_locks(nr_buckets) * sizeof(struct bucket_lock));
}

static void free_entry(struct __hash *h, void *p)
{
    free(p);
}

static void free_buckets(struct __hash *h,
                         struct bucket *buckets,
                         struct bucket_lock *bucket_locks)
{
    free(buckets);
    free(bucket_locks);
}

static int max_entries(struct __hash *h)
{
    /* There are no explicit restrictions to how many entries we can store */
    return -1;
}

#else

/*****************************************************************************/
/** Memory allocator for shared memory region **/
/*****************************************************************************/
#define SHM_TABLE_SLOTS 4

struct shm_hdr
{
    int             hash_allocated;
    pthread_mutex_t mutex;
    int             free_tab_slots[SHM_TABLE_SLOTS];

    unsigned long   freelist_offset;
                    
    unsigned long   entries_offset;
    unsigned long   nr_entries;
                    
    unsigned long   tabs_offset;
    unsigned long   max_tab_size;
    unsigned long   max_lock_tab_size;

    struct __hash   hash;
};

static unsigned long get_shm_baddr(void *hdr)
{
    return ((unsigned long)hdr - offsetof(struct shm_hdr, hash));
}


/** Locations of various structures/memory areas **/
static struct shm_hdr* get_shm_hdr(struct __hash *h)
{
    return (struct shm_hdr *)
            ((unsigned long)h - offsetof(struct shm_hdr, hash));
}

static uint32_t* get_shm_freelist(struct shm_hdr *hdr)
{
    unsigned long shm_baddr = (unsigned long)hdr;
    return ((uint32_t *)(shm_baddr + hdr->freelist_offset));
}

static struct hash_entry* get_shm_entries(struct shm_hdr *hdr)
{
    unsigned long shm_baddr = (unsigned long)hdr;
    return ((struct hash_entry *)(shm_baddr + hdr->entries_offset));
}

static struct bucket* get_shm_tab(struct shm_hdr *hdr, int i)
{
    unsigned long shm_baddr = (unsigned long)hdr;
    return ((struct bucket *)
               ((shm_baddr + hdr->tabs_offset) +
                 i * (hdr->max_tab_size + hdr->max_lock_tab_size)));
}

static struct bucket_lock* get_shm_lock_tab(struct shm_hdr *hdr, int i)
{
    unsigned long shm_baddr = (unsigned long)hdr;
    return ((struct bucket_lock *)
               ((shm_baddr + hdr->tabs_offset) +
                 i * (hdr->max_tab_size + hdr->max_lock_tab_size) +
                 hdr->max_tab_size));
}

static int get_shm_slot(struct shm_hdr *hdr, void *p)
{
    unsigned long shm_baddr = (unsigned long)hdr;
    return ((unsigned long)p - (shm_baddr + hdr->tabs_offset)) /
              (hdr->max_tab_size + hdr->max_lock_tab_size);
}

/* Shared memory allocator locks */
static int shm_mutex_init(struct shm_hdr *h)
{
    int ret;
    pthread_mutexattr_t _attr;

    ret = pthread_mutexattr_init(&_attr);
    if(ret == 0)
        ret = pthread_mutexattr_setpshared(&_attr, PTHREAD_PROCESS_SHARED);
    if(ret == 0)
        ret = pthread_mutex_init(&h->mutex, &_attr);
    if(ret == 0)
        ret = pthread_mutexattr_destroy(&_attr);

    return ret;
};

static int shm_mutex_lock(struct shm_hdr *h)
{
    return pthread_mutex_lock(&h->mutex);
}

static int shm_mutex_unlock(struct shm_hdr *h)
{
    return pthread_mutex_unlock(&h->mutex);
}


/* Shared memory allocator freelist */
static void shm_add_to_freelist(struct shm_hdr *hdr, uint32_t sl)
{
    uint32_t *freelist = get_shm_freelist(hdr);

    shm_mutex_lock(hdr);
    freelist[sl+1] = freelist[0];
    freelist[0] = sl;
    shm_mutex_unlock(hdr);
}

static uint32_t shm_get_from_freelist(struct shm_hdr *hdr)
{
    uint32_t *freelist = get_shm_freelist(hdr);
    uint32_t slot;

    shm_mutex_lock(hdr);
    slot = freelist[0];
    freelist[0] = freelist[slot+1];
    shm_mutex_unlock(hdr);

    return (slot == 0 ? -1 : slot);
}


#define SHM_ALLOC_MAIN(_n)

static unsigned long shm_init_offsets(
                                    struct shm_hdr *hdr, int nr_entries)
{
    hdr->freelist_offset = sizeof(struct shm_hdr);

    /* Freelist needs one extra slot in the array for the freelist head */
    hdr->entries_offset =
        hdr->freelist_offset + (nr_entries + 1) * sizeof(uint32_t);
    hdr->nr_entries = nr_entries;

    hdr->tabs_offset = hdr->entries_offset +
        nr_entries * sizeof(struct hash_entry);
    /* We want to allocate table 1.5 larger than the number of entries
       we want to hold in it */
    hdr->max_tab_size =
        (nr_entries * 3 / 2) * sizeof(struct bucket);
    hdr->max_lock_tab_size =
        nr_locks(hdr->max_tab_size) * sizeof(struct bucket_lock);

    return hdr->tabs_offset + (hdr->max_tab_size + hdr->max_lock_tab_size) * 4;
}

struct __hash* __shm_hash_init(unsigned long shm_baddr, unsigned long shm_size)
{
    uint32_t i;
    struct shm_hdr *hdr;

    /* Some sanity checks */
    hdr = (struct shm_hdr *)shm_baddr;
    memset(hdr, 0, sizeof(struct shm_hdr));

    /* Find the maximum number of entries we can store in the given shm_size */
    for(i=1; shm_init_offsets(hdr, i) < shm_size; i++){};
    shm_init_offsets(hdr, (i-1));

    memset(get_shm_freelist(hdr), 0,
           (hdr->nr_entries + 1) * sizeof(uint32_t));
    if(shm_mutex_init(hdr) != 0)
        return NULL;
    for(i=0; i<hdr->nr_entries; i++)
        shm_add_to_freelist(hdr, i);
    for(i=0; i<SHM_TABLE_SLOTS; i++)
        hdr->free_tab_slots[i] = 1;

    shm_mutex_lock(hdr);
    assert(!hdr->hash_allocated);
    hdr->hash_allocated = 1;
    shm_mutex_unlock(hdr);

    return __hash_init(&hdr->hash, 1000);
}

struct __hash* __shm_hash_get(unsigned long shm_baddr)
{
    struct shm_hdr *hdr = (struct shm_hdr *)shm_baddr;

    return (hdr->hash_allocated ? &hdr->hash : NULL);
}

static void* alloc_entry(struct __hash *h, int size)
{
    struct shm_hdr *hdr = get_shm_hdr(h);
    uint32_t slot = shm_get_from_freelist(hdr);

    assert(size == sizeof(struct hash_entry));
    if(slot == -1)
        return NULL;

    return (get_shm_entries(hdr) + slot);
}

static void alloc_buckets(struct __hash *h,
                          int nr_buckets,
                          struct bucket **buckets_tab,
                          struct bucket_lock **bucket_locks_tab)
{
    struct shm_hdr *hdr = get_shm_hdr(h);
    int free_slot;

    *buckets_tab = NULL;
    *bucket_locks_tab = NULL;

    if(((nr_buckets * sizeof(struct bucket)) > hdr->max_tab_size) ||
       ((nr_locks(nr_buckets) * sizeof(struct bucket_lock)) >
                                                hdr->max_lock_tab_size))
        return;

    shm_mutex_lock(hdr);
    for(free_slot=0; free_slot<SHM_TABLE_SLOTS; free_slot++)
        if(hdr->free_tab_slots[free_slot])
            break;
    if(free_slot == SHM_TABLE_SLOTS)
    {
        shm_mutex_unlock(hdr);
        return;
    }
    hdr->free_tab_slots[free_slot] = 0;
    shm_mutex_unlock(hdr);
    *buckets_tab      = get_shm_tab(hdr, free_slot);
    *bucket_locks_tab = get_shm_lock_tab(hdr, free_slot);
}

static void free_entry(struct __hash *h, void *p)
{
    struct shm_hdr *hdr = get_shm_hdr(h);
    uint32_t slot;

    slot = ((uint32_t)((struct hash_entry *)p -
                get_shm_entries(hdr)));
    shm_add_to_freelist(hdr, slot);
}

static void free_buckets(struct __hash *h,
                         struct bucket *buckets,
                         struct bucket_lock *bucket_locks)
{
    struct shm_hdr *hdr = get_shm_hdr(h);
    int slot;

    if(!buckets || !bucket_locks)
    {
        assert(!buckets && !bucket_locks);
        return;
    }
    slot = get_shm_slot(hdr, buckets);
    assert(slot < SHM_TABLE_SLOTS);
    assert((char *)bucket_locks == (char *)buckets + hdr->max_tab_size);
    shm_mutex_lock(hdr);
    assert(hdr->free_tab_slots[slot] == 0);
    hdr->free_tab_slots[slot] = 1;
    shm_mutex_unlock(hdr);
}

static int max_entries(struct __hash *h)
{
    struct shm_hdr *hdr = get_shm_hdr(h);

    return hdr->nr_entries;
}

#endif /* !BIDIR_USE_STDMALLOC */


/* The structures may be stored in shared memory region, with base address */
/* stored in shm_base_addr. All the pointers in the above structures need  */
/* to be relative to this base address (otherwise they would not make      */
/* sense to other processes). Bellow accessor functions are used to        */
/* convert between canonical (base address relative) and local addresses.  */
/* C2L stands for CANONICAL_TO_LOCAL, and vice versa                       */
#define C2L(_h, _p) ((typeof(_p))((unsigned long)(_p) +                        \
            get_shm_baddr(_h)))
#define L2C(_h, _p) ((typeof(_p))((unsigned long)(_p) -                        \
            get_shm_baddr(_h)))


#define HASH_LOCK_INIT(_h) ({                                                  \
    int _ret;                                                                  \
    pthread_rwlockattr_t _attr;                                                \
                                                                               \
    h->lock_alive = 1;                                                         \
    _ret = pthread_rwlockattr_init(&_attr);                                    \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlockattr_setpshared(&_attr,                           \
                                             PTHREAD_PROCESS_SHARED);          \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlock_init(&(_h)->hash_lock, &_attr);                  \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlockattr_destroy(&_attr);                             \
                                                                               \
    _ret;                                                                      \
})

#define HASH_LOCK_RDLOCK(_h) ({                                                \
    int _ret;                                                                  \
                                                                               \
    if(!_h->lock_alive) _ret = ENOLCK;                                         \
    else                                                                       \
    {                                                                          \
        struct timespec _ts;                                                   \
        /* 10s timeout, long but ~matches disk spin-up times */                \
        _ts.tv_sec = time(NULL) + 10;                                          \
        _ts.tv_nsec = 0;                                                       \
        _ret = pthread_rwlock_timedrdlock(&(_h)->hash_lock, &_ts);             \
        if(_ret == ETIMEDOUT) _h->lock_alive = 0;                              \
    }                                                                          \
    _ret;                                                                      \
})

#define HASH_LOCK_RDUNLOCK(_h)                                                 \
    pthread_rwlock_unlock(&(_h)->hash_lock)

#define HASH_LOCK_WRLOCK(_h) ({                                                \
    int _ret;                                                                  \
                                                                               \
    if(!_h->lock_alive) _ret = ENOLCK;                                         \
    else                                                                       \
    {                                                                          \
        struct timespec _ts;                                                   \
        _ts.tv_sec = time(NULL) + 10;                                          \
        _ts.tv_nsec = 0UL;                                                     \
        _ret = pthread_rwlock_timedwrlock(&(_h)->hash_lock, &_ts);             \
        if(_ret == ETIMEDOUT) _h->lock_alive = 0;                              \
    }                                                                          \
    _ret;                                                                      \
})

#define HASH_LOCK_TRYWRLOCK(_h) ({                                             \
    int _ret = (_h->lock_alive ?                                               \
                    pthread_rwlock_trywrlock(&(_h)->hash_lock) :               \
                    ENOLCK);                                                   \
    _ret;                                                                      \
})

#define HASH_LOCK_WRUNLOCK(_h)                                                 \
    pthread_rwlock_unlock(&(_h)->hash_lock)


#define BUCKET_LOCK_INIT(_h, _b) ({                                            \
    int _ret;                                                                  \
    pthread_rwlockattr_t _attr;                                                \
                                                                               \
    _ret = pthread_rwlockattr_init(&_attr);                                    \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlockattr_setpshared(&_attr,                           \
                                             PTHREAD_PROCESS_SHARED);          \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlock_init(&(_b)->bucket_lock, &_attr);                \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlockattr_destroy(&_attr);                             \
                                                                               \
    _ret;                                                                      \
})


#define BUCKET_LOCK_RDLOCK(_h, _lock_tab, _idx) ({                             \
    int _ret;                                                                  \
    struct timespec _ts;                                                       \
    struct bucket_lock *_lock = &(_lock_tab)[(_idx) / BUCKETS_PER_LOCK];       \
                                                                               \
    _ts.tv_sec = time(NULL) + 10;                                              \
    _ts.tv_nsec = 0;                                                           \
    _ret = pthread_rwlock_timedrdlock(&(_lock)->bucket_lock, &_ts);            \
    if(_ret == ETIMEDOUT) (_h)->lock_alive = 0;                                \
    _ret;                                                                      \
})


#define BUCKET_LOCK_RDUNLOCK(_h, _lock_tab, _idx) ({                           \
    struct bucket_lock *_lock = &(_lock_tab)[(_idx) / BUCKETS_PER_LOCK];       \
    pthread_rwlock_unlock(&(_lock)->bucket_lock);                              \
})

#define BUCKET_LOCK_WRLOCK(_h, _lock_tab, _idx) ({                             \
    int _ret;                                                                  \
    struct timespec _ts;                                                       \
    struct bucket_lock *_lock = &(_lock_tab)[(_idx) / BUCKETS_PER_LOCK];       \
                                                                               \
    _ts.tv_sec = time(NULL) + 10;                                              \
    _ts.tv_nsec = 0;                                                           \
    _ret = pthread_rwlock_timedwrlock(&(_lock)->bucket_lock, &_ts);            \
    if(_ret == ETIMEDOUT) (_h)->lock_alive = 0;                                \
    _ret;                                                                      \
})

#define BUCKET_LOCK_WRUNLOCK(_h, _lock_tab, _idx) ({                           \
    struct bucket_lock *_lock = &(_lock_tab)[(_idx) / BUCKETS_PER_LOCK];       \
    pthread_rwlock_unlock(&(_lock)->bucket_lock);                              \
})

#define TWO_BUCKETS_LOCK_WRLOCK(_h, _blt1, _idx1, _blt2, _idx2)  ({            \
    int _ret;                                                                  \
    pthread_rwlock_t *_l1, *_l2;                                               \
    struct timespec _ts;                                                       \
    struct bucket_lock *_bl1 = &(_blt1)[(_idx1) / BUCKETS_PER_LOCK];           \
    struct bucket_lock *_bl2 = &(_blt2)[(_idx2) / BUCKETS_PER_LOCK];           \
                                                                               \
    assert((_bl1) != (_bl2));                                                  \
    if((_bl1) < (_bl2))                                                        \
    {                                                                          \
        _l1 = &(_bl1)->bucket_lock;                                            \
        _l2 = &(_bl2)->bucket_lock;                                            \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        _l1 = &(_bl2)->bucket_lock;                                            \
        _l2 = &(_bl1)->bucket_lock;                                            \
    }                                                                          \
    _ts.tv_sec = time(NULL) + 10;                                              \
    _ts.tv_nsec = 0;                                                           \
    _ret = pthread_rwlock_timedwrlock(_l1, &_ts);                              \
    _ts.tv_sec = time(NULL) + 10;                                              \
    _ts.tv_nsec = 0;                                                           \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlock_timedwrlock(_l2, &_ts);                          \
    if(_ret == ETIMEDOUT) (_h)->lock_alive = 0;                                \
                                                                               \
    _ret;                                                                      \
})

#define TWO_BUCKETS_LOCK_WRUNLOCK(_h, _blt1, _idx1, _blt2, _idx2) ({           \
    int _ret;                                                                  \
    struct bucket_lock *_bl1 = &(_blt1)[(_idx1) / BUCKETS_PER_LOCK];           \
    struct bucket_lock *_bl2 = &(_blt2)[(_idx2) / BUCKETS_PER_LOCK];           \
                                                                               \
    _ret = pthread_rwlock_unlock(&(_bl1)->bucket_lock);                        \
    if(_ret == 0)                                                              \
        _ret = pthread_rwlock_unlock(&(_bl2)->bucket_lock);                    \
                                                                               \
    _ret;                                                                      \
})




static uint32_t hash_to_idx(struct __hash *h, uint32_t hash)
{
    return (hash % h->tab_size);
}

static void alloc_tab(struct __hash *h,
                      int size,
                      struct bucket **buckets_tab,
                      struct bucket_lock **bucket_locks_tab)
{
    int i;

    alloc_buckets(h, size, buckets_tab, bucket_locks_tab);
    if(!(*buckets_tab) || !(*bucket_locks_tab))
        goto error_out;
    memset(*buckets_tab, 0, size * sizeof(struct bucket));
    memset(*bucket_locks_tab, 0, nr_locks(size) * sizeof(struct bucket_lock));
    for(i=0; i<nr_locks(size); i++)
        if(BUCKET_LOCK_INIT(h, *bucket_locks_tab + i) != 0)
            goto error_out;

    return;
error_out:
    free_buckets(h, *buckets_tab, *bucket_locks_tab);
    *buckets_tab = NULL;
    *bucket_locks_tab = NULL;
    return;
}


struct __hash *__hash_init(struct __hash *h, uint32_t min_size)
{
    uint32_t size;
    uint16_t size_idx;
    struct bucket *buckets;
    struct bucket_lock *bucket_locks;

    /* Sanity check on args */
    if (min_size > hash_sizes[hash_sizes_len-1]) return NULL;
    /* Find least size greater than init_size */
    for(size_idx = 0; size_idx < hash_sizes_len; size_idx++)
            if(hash_sizes[size_idx] >= min_size)
                break;
    size = hash_sizes[size_idx];

    if(!h) return NULL;
    alloc_tab(h, size, &buckets, &bucket_locks);
    if(!buckets || !bucket_locks) goto alloc_fail;
    h->key_tab         = L2C(h, buckets);
    h->key_lock_tab    = L2C(h, bucket_locks);
    alloc_tab(h, size, &buckets, &bucket_locks);
    if(!buckets || !bucket_locks) goto alloc_fail;
    h->value_tab       = L2C(h, buckets);
    h->value_lock_tab  = L2C(h, bucket_locks);
    /* Init all h variables */
    if(HASH_LOCK_INIT(h) != 0) goto alloc_fail;
    h->nr_ent = 0;
    h->tab_size = size;
    h->size_idx = size_idx;
    h->max_load = (uint32_t)ceilf(hash_max_load_fact * size);
    h->min_load = (uint32_t)ceilf(hash_min_load_fact * size);

    return h;

alloc_fail:
    if(h->key_tab || h->key_lock_tab)
        free_buckets(h, C2L(h, h->key_tab), C2L(h, h->key_lock_tab));
    return NULL;
}

#undef __prim
#undef __prim_t
#undef __prim_tab
#undef __prim_lock_tab
#undef __prim_hash
#undef __prim_cmp
#undef __prim_next
#undef __sec
#undef __sec_t

#define __prim             key
#define __prim_t         __k_t
#define __prim_tab         key_tab
#define __prim_lock_tab    key_lock_tab
#define __prim_hash      __key_hash
#define __prim_cmp       __key_cmp
#define __prim_next        key_next
#define __sec              value
#define __sec_t          __v_t
int __key_lookup(struct __hash *h, __prim_t k, __sec_t *vp)
{
    struct hash_entry *entry;
    struct bucket *b;
    struct bucket_lock *blt;
    uint32_t idx;

    if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;
    idx = hash_to_idx(h, __prim_hash(k));
    b = C2L(h, &h->__prim_tab[idx]);
    blt = C2L(h, h->__prim_lock_tab);
    if(BUCKET_LOCK_RDLOCK(h, blt, idx) != 0) return -ENOLCK;
    entry = b->hash_entry;
    while(entry != NULL)
    {
        entry = C2L(h, entry);
        if(__prim_cmp(k, entry->__prim))
        {
            /* Unlock here */
            *vp = entry->__sec;
            BUCKET_LOCK_RDUNLOCK(h, blt, idx);
            HASH_LOCK_RDUNLOCK(h);
            return 1;
        }
        entry = entry->__prim_next;
    }
    BUCKET_LOCK_RDUNLOCK(h, blt, idx);
    HASH_LOCK_RDUNLOCK(h);
    return 0;
}

/* value lookup is an almost exact copy of key lookup */
#undef __prim
#undef __prim_t
#undef __prim_tab
#undef __prim_lock_tab
#undef __prim_hash
#undef __prim_cmp
#undef __prim_next
#undef __sec
#undef __sec_t

#define __prim             value
#define __prim_t         __v_t
#define __prim_tab         value_tab
#define __prim_lock_tab    value_lock_tab
#define __prim_hash      __value_hash
#define __prim_cmp       __value_cmp
#define __prim_next        value_next
#define __sec              key
#define __sec_t          __k_t
int __value_lookup(struct __hash *h, __prim_t k, __sec_t *vp)
{
    struct hash_entry *entry;
    struct bucket *b;
    struct bucket_lock *blt;
    uint32_t idx;

    if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;
    idx = hash_to_idx(h, __prim_hash(k));
    b = C2L(h, &h->__prim_tab[idx]);
    blt = C2L(h, h->__prim_lock_tab);
    if(BUCKET_LOCK_RDLOCK(h, blt, idx) != 0) return -ENOLCK;
    entry = b->hash_entry;
    while(entry != NULL)
    {
        entry = C2L(h, entry);
        if(__prim_cmp(k, entry->__prim))
        {
            /* Unlock here */
            *vp = entry->__sec;
            BUCKET_LOCK_RDUNLOCK(h, blt, idx);
            HASH_LOCK_RDUNLOCK(h);
            return 1;
        }
        entry = entry->__prim_next;
    }
    BUCKET_LOCK_RDUNLOCK(h, blt, idx);
    HASH_LOCK_RDUNLOCK(h);
    return 0;
}

int __insert(struct __hash *h, __k_t k, __v_t v)
{
    uint32_t k_idx, v_idx;
    struct hash_entry *entry;
    struct bucket *bk, *bv;
    struct bucket_lock *bltk, *bltv;

    /* Allocate new entry before any locks (in case it fails) */
    entry = (struct hash_entry*)
                    alloc_entry(h, sizeof(struct hash_entry));
    if(!entry) return 0;

    if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;
    /* Read from nr_ent is atomic(TODO check), no need for fancy accessors */
    if(h->nr_ent+1 > h->max_load)
    {
        /* Resize needs the write lock, drop read lock temporarily */
        HASH_LOCK_RDUNLOCK(h);
        hash_resize(h);
        if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;
    }

    /* Init the entry */
    entry->key = k;
    entry->value = v;

    /* Work out the indicies */
    k_idx = hash_to_idx(h, __key_hash(k));
    v_idx = hash_to_idx(h, __value_hash(v));

    /* Insert */
    bk   = C2L(h, &h->key_tab[k_idx]);
    bv   = C2L(h, &h->value_tab[v_idx]);
    bltk = C2L(h, h->key_lock_tab);
    bltv = C2L(h, h->value_lock_tab);
    if(TWO_BUCKETS_LOCK_WRLOCK(h, bltk, k_idx, bltv, v_idx) != 0)
        return -ENOLCK;
    entry->key_next = bk->hash_entry;
    bk->hash_entry = L2C(h, entry);
    entry->value_next = bv->hash_entry;
    bv->hash_entry = L2C(h, entry);
    TWO_BUCKETS_LOCK_WRUNLOCK(h, bltk, k_idx, bltv, v_idx);

    /* Book keeping */
    atomic_inc(&h->nr_ent);

    HASH_LOCK_RDUNLOCK(h);

    return 1;
}


#undef __prim
#undef __prim_t
#undef __prim_tab
#undef __prim_lock_tab
#undef __prim_hash
#undef __prim_cmp
#undef __prim_next
#undef __sec
#undef __sec_t
#undef __sec_tab
#undef __sec_lock_tab
#undef __sec_hash
#undef __sec_next

#define __prim             key
#define __prim_t         __k_t
#define __prim_tab         key_tab
#define __prim_lock_tab    key_lock_tab
#define __prim_hash      __key_hash
#define __prim_cmp       __key_cmp
#define __prim_next        key_next
#define __sec              value
#define __sec_t          __v_t
#define __sec_tab          value_tab
#define __sec_lock_tab     value_lock_tab
#define __sec_hash       __value_hash
#define __sec_next         value_next

int __key_remove(struct __hash *h, __prim_t k, __sec_t *vp)
{
    struct hash_entry *e, *es, **pek, **pev;
    struct bucket *bk, *bv;
    struct bucket_lock *bltk, *bltv;
    uint32_t old_kidx, kidx, vidx, min_load, nr_ent;
    __prim_t ks;
    __sec_t vs;

    if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;

again:
    old_kidx = kidx = hash_to_idx(h, __prim_hash(k));
    bk = C2L(h, &h->__prim_tab[kidx]);
    bltk = C2L(h, h->__prim_lock_tab);
    if(BUCKET_LOCK_RDLOCK(h, bltk, kidx) != 0) return -ENOLCK;
    pek = &(bk->hash_entry);
    e = *pek;
    while(e != NULL)
    {
        e = C2L(h, e);
        if(__prim_cmp(k, e->__prim))
        {
            goto found;
        }
        pek = &(e->__prim_next);
        e = *pek;
    }

    BUCKET_LOCK_RDUNLOCK(h, bltk, kidx);
    HASH_LOCK_RDUNLOCK(h);

    return 0;

found:
    /*
     * Make local copy of key and value.
     */
    es = e;
    ks = e->__prim;
    vs = e->__sec;
    kidx = hash_to_idx(h, __prim_hash(ks));
    /* Being paranoid: check if kidx has not changed, so that we unlock the
     * right bucket */
    assert(old_kidx == kidx);
    vidx = hash_to_idx(h, __sec_hash(vs));
    bk   = C2L(h, &h->__prim_tab[kidx]);
    bv   = C2L(h, &h->__sec_tab[vidx]);
    bltk = C2L(h, h->__prim_lock_tab);
    bltv = C2L(h, h->__sec_lock_tab);
    BUCKET_LOCK_RDUNLOCK(h, bltk, kidx);
    if(TWO_BUCKETS_LOCK_WRLOCK(h, bltk, kidx, bltv, vidx) != 0) return -ENOLCK;
    pek = &(bk->hash_entry);
    pev = &(bv->hash_entry);

    /* Find the entry in both tables */
    e = *pek;
    while(e != NULL)
    {
        e = C2L(h, e);
        if(e == es)
        {
            /* Being paranoid: make sure that the key and value are
             * still the same. This is still not 100%, because, in
             * principle, the entry could have got deleted, when we
             * didn't hold the locks for a little while, and exactly
             * the same entry reinserted. If the __k_t & __v_t are
             * simple types than it probably doesn't matter, but if
             * either is a pointer type, the actual structure might
             * now be different. The chances that happens are very
             * slim, but still, if that's a problem, the user needs to
             * pay attention to the structure re-allocation */
            if((memcmp(&(e->__prim), &ks, sizeof(__prim_t))) ||
               (memcmp(&(e->__sec), &vs, sizeof(__sec_t))))
                break;
            goto found_again;
        }
        pek = &(e->__prim_next);
        e = *pek;
    }

    TWO_BUCKETS_LOCK_WRUNLOCK(h, bltk, kidx, bltv, vidx);

    /* Entry got removed in the meantime, try again */
    goto again;

found_again:
    /* We are now comitted to the removal */
    e = *pev;
    while(e != NULL)
    {
        e = C2L(h, e);
        if(e == es)
        {
            /* Both pek and pev are pointing to the right place, remove */
            *pek = e->__prim_next;
            *pev = e->__sec_next;

            atomic_dec(&h->nr_ent);
            nr_ent = h->nr_ent;
            /* read min_load still under the hash lock! */
            min_load = h->min_load;

            TWO_BUCKETS_LOCK_WRUNLOCK(h, bltk, kidx, bltv, vidx);
            HASH_LOCK_RDUNLOCK(h);

            if(nr_ent < min_load)
                hash_resize(h);
            if(vp != NULL)
                *vp = e->__sec;
            free_entry(h, e);
            return 1;
        }
        pev = &(e->__sec_next);
        e = *pev;
    }

    /* We should never get here!, no need to unlock anything */
    return -ENOLCK;
}

#undef __prim
#undef __prim_t
#undef __prim_tab
#undef __prim_lock_tab
#undef __prim_hash
#undef __prim_cmp
#undef __prim_next
#undef __sec
#undef __sec_t
#undef __sec_tab
#undef __sec_lock_tab
#undef __sec_hash
#undef __sec_next

#define __prim             value
#define __prim_t         __v_t
#define __prim_tab         value_tab
#define __prim_lock_tab    value_lock_tab
#define __prim_hash      __value_hash
#define __prim_cmp       __value_cmp
#define __prim_next        value_next
#define __sec              key
#define __sec_t          __k_t
#define __sec_tab          key_tab
#define __sec_lock_tab     key_lock_tab
#define __sec_hash       __key_hash
#define __sec_next         key_next

int __value_remove(struct __hash *h, __prim_t k, __sec_t *vp)
{
    struct hash_entry *e, *es, **pek, **pev;
    struct bucket *bk, *bv;
    struct bucket_lock *bltk, *bltv;
    uint32_t old_kidx, kidx, vidx, min_load, nr_ent;
    __prim_t ks;
    __sec_t vs;

    if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;

again:
    old_kidx = kidx = hash_to_idx(h, __prim_hash(k));
    bk = C2L(h, &h->__prim_tab[kidx]);
    bltk = C2L(h, h->__prim_lock_tab);
    if(BUCKET_LOCK_RDLOCK(h, bltk, kidx) != 0) return -ENOLCK;
    pek = &(bk->hash_entry);
    e = *pek;
    while(e != NULL)
    {
        e = C2L(h, e);
        if(__prim_cmp(k, e->__prim))
        {
            goto found;
        }
        pek = &(e->__prim_next);
        e = *pek;
    }

    BUCKET_LOCK_RDUNLOCK(h, bltk, kidx);
    HASH_LOCK_RDUNLOCK(h);

    return 0;

found:
    /*
     * Make local copy of key and value.
     */
    es = e;
    ks = e->__prim;
    vs = e->__sec;
    kidx = hash_to_idx(h, __prim_hash(ks));
    /* Being paranoid: check if kidx has not changed, so that we unlock the
     * right bucket */
    assert(old_kidx == kidx);
    vidx = hash_to_idx(h, __sec_hash(vs));
    bk   = C2L(h, &h->__prim_tab[kidx]);
    bv   = C2L(h, &h->__sec_tab[vidx]);
    bltk = C2L(h, h->__prim_lock_tab);
    bltv = C2L(h, h->__sec_lock_tab);
    BUCKET_LOCK_RDUNLOCK(h, bltk, kidx);
    if(TWO_BUCKETS_LOCK_WRLOCK(h, bltk, kidx, bltv, vidx) != 0) return -ENOLCK;
    pek = &(bk->hash_entry);
    pev = &(bv->hash_entry);

    /* Find the entry in both tables */
    e = *pek;
    while(e != NULL)
    {
        e = C2L(h, e);
        if(e == es)
        {
            /* Being paranoid: make sure that the key and value are
             * still the same. This is still not 100%, because, in
             * principle, the entry could have got deleted, when we
             * didn't hold the locks for a little while, and exactly
             * the same entry reinserted. If the __k_t & __v_t are
             * simple types than it probably doesn't matter, but if
             * either is a pointer type, the actual structure might
             * now be different. The chances that happens are very
             * slim, but still, if that's a problem, the user needs to
             * pay attention to the structure re-allocation */
            if((memcmp(&(e->__prim), &ks, sizeof(__prim_t))) ||
               (memcmp(&(e->__sec), &vs, sizeof(__sec_t))))
                break;
            goto found_again;
        }
        pek = &(e->__prim_next);
        e = *pek;
    }

    TWO_BUCKETS_LOCK_WRUNLOCK(h, bltk, kidx, bltv, vidx);

    /* Entry got removed in the meantime, try again */
    goto again;

found_again:
    /* We are now comitted to the removal */
    e = *pev;
    while(e != NULL)
    {
        e = C2L(h, e);
        if(e == es)
        {
            /* Both pek and pev are pointing to the right place, remove */
            *pek = e->__prim_next;
            *pev = e->__sec_next;

            atomic_dec(&h->nr_ent);
            nr_ent = h->nr_ent;
            /* read min_load still under the hash lock! */
            min_load = h->min_load;

            TWO_BUCKETS_LOCK_WRUNLOCK(h, bltk, kidx, bltv, vidx);
            HASH_LOCK_RDUNLOCK(h);

            if(nr_ent < min_load)
                hash_resize(h);
            if(vp != NULL)
                *vp = e->__sec;
            free_entry(h, e);
            return 1;
        }
        pev = &(e->__sec_next);
        e = *pev;
    }

    /* We should never get here!, no need to unlock anything */
    return -ENOLCK;
}


int __hash_destroy(struct __hash *h,
                   void (*entry_consumer)(__k_t k, __v_t v, void *p),
                   void *d)
{
    struct hash_entry *e, *n;
    struct bucket *b;
    int i;

    if(HASH_LOCK_WRLOCK(h) != 0) return -ENOLCK;

    /* No need to lock individual buckets, with hash write lock  */
    for(i=0; i < h->tab_size; i++)
    {
        b = C2L(h, &h->key_tab[i]);
        e = b->hash_entry;
        while(e != NULL)
        {
            e = C2L(h, e);
            n = e->key_next;
            if(entry_consumer)
                entry_consumer(e->key, e->value, d);
            free_entry(h, e);
            e = n;
        }
    }
    free_buckets(h, C2L(h, h->key_tab), C2L(h, h->key_lock_tab));
    free_buckets(h, C2L(h, h->value_tab), C2L(h, h->value_lock_tab));

    HASH_LOCK_WRUNLOCK(h);
    h->lock_alive = 0;

    return 0;
}

static void hash_resize(struct __hash *h)
{
    int new_size_idx, i, lock_ret;
    uint32_t size, old_size, kidx, vidx;
    struct bucket *t1, *t2, *b;
    struct bucket_lock *l1, *l2;
    struct hash_entry *e, *n;

    /* We may fail to allocate the lock, if the resize is triggered while
       we are iterating (under read lock) */
    lock_ret = HASH_LOCK_TRYWRLOCK(h);
    if(lock_ret != 0) return;

    new_size_idx = h->size_idx;
    /* Work out the new size */
    if(h->nr_ent >= h->max_load)
        new_size_idx = h->size_idx+1;
    if(h->nr_ent < h->min_load)
        new_size_idx = h->size_idx-1;
    if((new_size_idx == h->size_idx) ||
       (new_size_idx >= hash_sizes_len) ||
       (new_size_idx < 0))
    {
        HASH_LOCK_WRUNLOCK(h);
        return;
    }

    size = hash_sizes[new_size_idx];

    /* Allocate the new sizes */
    t1 = t2 = NULL;
    l1 = l2 = NULL;
    alloc_tab(h, size, &t1, &l1);
    if(!t1 || !l1) goto alloc_fail;
    alloc_tab(h, size, &t2, &l2);
    if(!t2 || !l2) goto alloc_fail;

    old_size = h->tab_size;
    h->tab_size = size;
    h->size_idx = new_size_idx;
    h->max_load = (uint32_t)ceilf(hash_max_load_fact * size);
    h->min_load = (uint32_t)ceilf(hash_min_load_fact * size);

    /* Move the entries */
    for(i=0; i < old_size; i++)
    {
        b = C2L(h, &h->key_tab[i]);
        e = b->hash_entry;
        while(e != NULL)
        {
            e = C2L(h, e);
            n = e->key_next;
            kidx =hash_to_idx(h, __key_hash(e->key));
            vidx =hash_to_idx(h, __value_hash(e->value));
            /* Move to the correct bucket */
            e->key_next = t1[kidx].hash_entry;
            t1[kidx].hash_entry = L2C(h, e);
            e->value_next = t2[vidx].hash_entry;
            t2[vidx].hash_entry = L2C(h, e);
            e = n;
        }
    }
    free_buckets(h, C2L(h, h->key_tab), C2L(h, h->key_lock_tab));
    free_buckets(h, C2L(h, h->value_tab), C2L(h, h->value_lock_tab));
    h->key_tab         = L2C(h, t1);
    h->key_lock_tab    = L2C(h, l1);
    h->value_tab       = L2C(h, t2);
    h->value_lock_tab  = L2C(h, l2);

    HASH_LOCK_WRUNLOCK(h);

    return;

alloc_fail:
    /* If we failed to resize, adjust max/min load. This will stop us from
     * retrying resize too frequently */ 
    if(new_size_idx > h->size_idx)
        h->max_load = (h->max_load + 2 * h->tab_size) / 2 + 1;
    else 
    if (new_size_idx < h->size_idx)
        h->min_load = h->min_load / 2;
    HASH_LOCK_WRUNLOCK(h);
    if(t1 || l1) free_buckets(h, t1, l1);
    if(t2 || l2) free_buckets(h, t2, l2);
    return;
}

int __hash_iterator(struct __hash *h,
                    int (*entry_consumer)(__k_t k, __v_t v, void *p),
                    void *d)
{
    struct hash_entry *e, *n;
    struct bucket *b;
    struct bucket_lock *blt;
    int i, brk_early;

    if(HASH_LOCK_RDLOCK(h) != 0) return -ENOLCK;

    for(i=0; i < h->tab_size; i++)
    {
        b = C2L(h, &h->key_tab[i]);
        blt = C2L(h, h->key_lock_tab);
        if(BUCKET_LOCK_RDLOCK(h, blt, i) != 0) return -ENOLCK;
        e = b->hash_entry;
        while(e != NULL)
        {
            e = C2L(h, e);
            n = e->key_next;
            brk_early = entry_consumer(e->key, e->value, d);
            if(brk_early)
            {
                BUCKET_LOCK_RDUNLOCK(h, blt, i);
                goto out;
            }
            e = n;
        }
        BUCKET_LOCK_RDUNLOCK(h, blt, i);
    }
out:
    HASH_LOCK_RDUNLOCK(h);
    return 0;
}

void __hash_sizes(struct __hash *h,
                  uint32_t *nr_ent,
                  uint32_t *max_nr_ent,
                  uint32_t *tab_size,
                  uint32_t *max_load,
                  uint32_t *min_load)
{
    if(nr_ent     != NULL) *nr_ent     = h->nr_ent;
    if(max_nr_ent != NULL) *max_nr_ent = max_entries(h); 
    if(tab_size   != NULL) *tab_size   = h->tab_size;
    if(max_load   != NULL) *max_load   = h->max_load;
    if(min_load   != NULL) *min_load   = h->min_load;
}

