/*
 * Copyright (C) 2001 - 2004 Mike Wray <mike.wray@hp.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef __KERNEL__
#  include <linux/config.h>
#  include <linux/module.h>
#  include <linux/kernel.h>
#  include <linux/errno.h>
#else
#  include <errno.h>
#  include <stddef.h>
#endif

//#include <limits.h>

#include "allocate.h"
#include "hash_table.h"

/** @file
 * Base support for hashtables.
 *
 * Hash codes are reduced modulo the number of buckets to index tables,
 * so there is no need for hash functions to limit the range of hashcodes.
 * In fact it is assumed that hashcodes do not change when the number of
 * buckets in the table changes.
 */

/*==========================================================================*/
/** Number of bits in half a word. */
//#if __WORDSIZE == 64
//#define HALF_WORD_BITS 32
//#else
#define HALF_WORD_BITS 16
//#endif

/** Mask for lo half of a word. On 32-bit this is 
 * (1<<16) - 1 = 65535 = 0xffff
 * It's 4294967295 = 0xffffffff on 64-bit.
 */
#define LO_HALF_MASK ((1 << HALF_WORD_BITS) - 1)

/** Get the lo half of a word. */
#define LO_HALF(x) ((x) & LO_HALF_MASK)

/** Get the hi half of a word. */
#define HI_HALF(x) ((x) >> HALF_WORD_BITS)

/** Do a full hash on both inputs, using DES-style non-linear scrambling.
 * Both inputs are replaced with the results of the hash.
 *
 * @param pleft input/output word
 * @param pright input/output word
 */
void pseudo_des(unsigned long *pleft, unsigned long *pright){
    // Bit-rich mixing constant.
    static const unsigned long a_mixer[] = {
        0xbaa96887L, 0x1e17d32cL, 0x03bcdc3cL, 0x0f33d1b2L, };

    // Bit-rich mixing constant.
    static const unsigned long b_mixer[] = {
        0x4b0f3b58L, 0xe874f0c3L, 0x6955c5a6L, 0x55a7ca46L, };

    // Number of iterations - must be 2 or 4.
    static const int ncycle = 4;
    //static const int ncycle = 2;

    unsigned long left = *pleft, right = *pright;
    unsigned long v, v_hi, v_lo;
    int i;

    for(i=0; i<ncycle; i++){
        // Flip some bits in right to get v.
        v = right;
        v ^= a_mixer[i];
        // Get lo and hi halves of v.
        v_lo = LO_HALF(v);
        v_hi = HI_HALF(v);
        // Non-linear mix of the halves of v.
        v = ((v_lo * v_lo) + ~(v_hi * v_hi));
        // Swap the halves of v.
        v = (HI_HALF(v) | (LO_HALF(v) << HALF_WORD_BITS));
        // Flip some bits.
        v ^= b_mixer[i];
        // More non-linear mixing.
        v += (v_lo * v_hi);
        v ^= left;
        left = right;
        right = v;
    }
    *pleft = left;
    *pright = right;
}

/** Hash a string.
 *
 * @param s input to hash
 * @return hashcode
 */
Hashcode hash_string(char *s){
    Hashcode h = 0;
    if(s){
        for( ; *s; s++){
            h = hash_2ul(h, *s);
        }
    }
    return h;
}

/** Get the bucket for a hashcode in a hash table.
 *
 * @param table to get bucket from
 * @param hashcode to get bucket for
 * @return bucket
 */
inline HTBucket * get_bucket(HashTable *table, Hashcode hashcode){
    return table->buckets + (hashcode % table->buckets_n);
}

/** Initialize a hash table.
 * Can be safely called more than once.
 *
 * @param table to initialize
 */
void HashTable_init(HashTable *table){
    int i;

    if(!table->init_done){
        table->init_done = 1;
        table->next_id = 0;
        for(i=0; i<table->buckets_n; i++){
            HTBucket *bucket = get_bucket(table, i);
            bucket->head = 0;
            bucket->count = 0;
        }
        table->entry_count = 0;
    }
}

/** Allocate a new hashtable.
 * If the number of buckets is not positive the default is used.
 * The number of buckets should usually be prime.
 *
 * @param buckets_n number of buckets
 * @return new hashtable or null
 */
HashTable *HashTable_new(int buckets_n){
    HashTable *z = ALLOCATE(HashTable);
    if(!z) goto exit;
    if(buckets_n <= 0){
        buckets_n = HT_BUCKETS_N;
    }
    z->buckets = (HTBucket*)allocate(buckets_n * sizeof(HTBucket));
    if(!z->buckets){
        deallocate(z);
        z = 0;
        goto exit;
    }
    z->buckets_n = buckets_n;
    HashTable_init(z);
  exit:
    return z;
}

/** Free a hashtable.
 * Any entries are removed and freed.
 *
 * @param h hashtable (ignored if null)
 */
void HashTable_free(HashTable *h){
    if(h){
        HashTable_clear(h);
        deallocate(h->buckets);
        deallocate(h);
    }
}

/** Push an entry on the list in the bucket for a given hashcode.
 *
 * @param table to add entry to
 * @param hashcode for the entry
 * @param entry to add
 */
static inline void push_on_bucket(HashTable *table, Hashcode hashcode,
				  HTEntry *entry){
    HTBucket *bucket;
    HTEntry *old_head;

    bucket = get_bucket(table, hashcode);
    old_head = bucket->head;
    bucket->count++;
    bucket->head = entry;
    entry->next = old_head;
}

/** Change the number of buckets in a hashtable.
 * No-op if the number of buckets is not positive.
 * Existing entries are reallocated to buckets based on their hashcodes.
 * The table is unmodified if the number of buckets cannot be changed.
 *
 * @param table hashtable
 * @param buckets_n new number of buckets
 * @return 0 on success, error code otherwise
 */
int HashTable_set_buckets_n(HashTable *table, int buckets_n){
    int err = 0;
    HTBucket *old_buckets = table->buckets;
    int old_buckets_n = table->buckets_n;
    int i;

    if(buckets_n <= 0){
        err = -EINVAL;
        goto exit;
    }
    table->buckets = (HTBucket*)allocate(buckets_n * sizeof(HTBucket));
    if(!table->buckets){
        err = -ENOMEM;
        table->buckets = old_buckets;
        goto exit;
    }
    table->buckets_n = buckets_n;
    for(i=0; i<old_buckets_n; i++){
        HTBucket *bucket = old_buckets + i;
        HTEntry *entry, *next;
        for(entry = bucket->head; entry; entry = next){
            next = entry->next;
            push_on_bucket(table, entry->hashcode, entry);
        }
    }
    deallocate(old_buckets);
  exit:
    return err;
}

/** Adjust the number of buckets so the table is neither too full nor too empty.
 * The table is unmodified if adjusting fails.
 *
 * @param table hash table
 * @param buckets_min minimum number of buckets (use default if 0 or negative)
 * @return 0 on success, error code otherwise
 */
int HashTable_adjust(HashTable *table, int buckets_min){
    int buckets_n = 0;
    int err = 0;
    if(buckets_min <= 0) buckets_min = HT_BUCKETS_N;
    if(table->entry_count >= table->buckets_n){
        // The table is dense - expand it.
        buckets_n = 2 * table->buckets_n;
    } else if((table->buckets_n > buckets_min) &&
              (4 * table->entry_count < table->buckets_n)){
        // The table is more than minimum size and sparse - shrink it.
        buckets_n = 2 * table->entry_count;
        if(buckets_n < buckets_min) buckets_n = buckets_min;
    }
    if(buckets_n){
        err = HashTable_set_buckets_n(table, buckets_n);
    }
    return err;
}

/** Allocate a new entry for a given value.
 *
 * @param value to put in the entry
 * @return entry, or 0 on failure
 */
HTEntry * HTEntry_new(Hashcode hashcode, void *key, void *value){
    HTEntry *z = ALLOCATE(HTEntry);
    if(z){
        z->hashcode = hashcode;
        z->key = key;
        z->value = value;
    }
    return z;
}

/** Free an entry.
 *
 * @param z entry to free
 */
inline void HTEntry_free(HTEntry *z){
    if(z){
        deallocate(z);
    }
}

/** Free an entry in a hashtable.
 * The table's entry_free_fn is used is defined, otherwise 
 * the HTEntry itself is freed.
 *
 * @param table hashtable
 * @param entry to free
 */
inline void HashTable_free_entry(HashTable *table, HTEntry *entry){
    if(!entry)return;
    if(table && table->entry_free_fn){
        table->entry_free_fn(table, entry);
    } else {
        HTEntry_free(entry);
    }
}

/** Get the first entry satisfying a test from the bucket for the
 * given hashcode.
 *
 * @param table to look in
 * @param hashcode indicates the bucket
 * @param test_fn test to apply to elements
 * @param arg first argument to calls to test_fn
 * @return entry found, or 0
 */
inline HTEntry * HashTable_find_entry(HashTable *table, Hashcode hashcode,
				      TableTestFn *test_fn, TableArg arg){
    HTBucket *bucket;
    HTEntry *entry = 0;
    HTEntry *next;

    bucket = get_bucket(table, hashcode);
    for(entry = bucket->head; entry; entry = next){
        next = entry->next;
        if(test_fn(arg, table, entry)){
            break;
        }
    }
    return entry;
}

/** Test hashtable keys for equality.
 * Uses the table's key_equal_fn if defined, otherwise pointer equality.
 *
 * @param key1 key to compare
 * @param key2 key to compare
 * @return 1 if equal, 0 otherwise
 */
inline int HashTable_key_equal(HashTable *table, void *key1, void *key2){
    return (table->key_equal_fn ? table->key_equal_fn(key1, key2) : key1==key2);
}

/** Compute the hashcode of a hashtable key.
 * The table's key_hash_fn is used if defined, otherwise the address of
 * the key is hashed.
 *
 * @param table hashtable
 * @param key to hash
 * @return hashcode
 */
inline Hashcode HashTable_key_hash(HashTable *table, void *key){
    return (table->key_hash_fn ? table->key_hash_fn(key) : hash_ul((unsigned long)key));
}

/** Test if an entry has a given key.
 *
 * @param arg containing key to test for
 * @param table the entry is in
 * @param entry to test
 * @return 1 if the entry has the key, 0 otherwise
 */
static inline int has_key(TableArg arg, HashTable *table, HTEntry *entry){
    return HashTable_key_equal(table, arg.ptr, entry->key);
}

/** Get an entry with a given key.
 *
 * @param table to search
 * @param key to look for
 * @return entry if found, null otherwise
 */
#if 0
inline HTEntry * HashTable_get_entry(HashTable *table, void *key){
    TableArg arg = { ptr: key };
    return HashTable_find_entry(table, HashTable_key_hash(table, key), has_key, arg);
}
#else
inline HTEntry * HashTable_get_entry(HashTable *table, void *key){
    Hashcode hashcode;
    HTBucket *bucket;
    HTEntry *entry = 0;
    HTEntry *next;

    hashcode = HashTable_key_hash(table, key);
    bucket = get_bucket(table, hashcode);
    for(entry = bucket->head; entry; entry = next){
        next = entry->next;
        if(HashTable_key_equal(table, key, entry->key)){
            break;
        }
    }
    return entry;
}
#endif

/** Get the value of an entry with a given key.
 *
 * @param table to search
 * @param key to look for
 * @return value if an entry was found, null otherwise
 */
inline void * HashTable_get(HashTable *table, void *key){
    HTEntry *entry = HashTable_get_entry(table, key);
    return (entry ? entry->value : 0);
}

/** Print the buckets in a table.
 *
 * @param table to print
 */
void show_buckets(HashTable *table, IOStream *io){
    int i,j ;
    IOStream_print(io, "entry_count=%d buckets_n=%d\n", table->entry_count, table->buckets_n);
    for(i=0; i<table->buckets_n; i++){
        if(0 || table->buckets[i].count>0){
            IOStream_print(io, "bucket %3d %3d %10p ", i,
                        table->buckets[i].count,
                        table->buckets[i].head);
            for(j = table->buckets[i].count; j>0; j--){
                IOStream_print(io, "+");
            }
            IOStream_print(io, "\n");
        }
    }
    HashTable_print(table, io); 
}
    
/** Print an entry in a table.
 *
 * @param entry to print
 * @param arg a pointer to an IOStream to print to
 * @return 0
 */
static int print_entry(TableArg arg, HashTable *table, HTEntry *entry){
    IOStream *io = (IOStream*)arg.ptr;
    IOStream_print(io, " b=%4lx h=%08lx i=%08lx |-> e=%8p k=%8p v=%8p\n",
                entry->hashcode % table->buckets_n,
                entry->hashcode,
                entry->index,
                entry, entry->key, entry->value);
    return 0;
}

/** Print a hash table.
 *
 * @param table to print
 */
void HashTable_print(HashTable *table, IOStream *io){
    IOStream_print(io, "{\n");
    HashTable_map(table, print_entry, (TableArg){ ptr: io });
    IOStream_print(io, "}\n");
}
/*==========================================================================*/

/** Get the next entry id to use for a table.
 *
 * @param table hash table
 * @return non-zero entry id
 */
static inline unsigned long get_next_id(HashTable *table){
    unsigned long id;

    if(table->next_id == 0){
        table->next_id = 1;
    }
    id = table->next_id++;
    return id;
}

/** Add an entry to the bucket for the
 * given hashcode.
 *
 * @param table to insert in
 * @param hashcode indicates the bucket
 * @param key to add an entry for
 * @param value to add an entry for
 * @return entry on success, 0 on failure
 */
inline HTEntry * HashTable_add_entry(HashTable *table, Hashcode hashcode, void *key, void *value){
    HTEntry *entry = HTEntry_new(hashcode, key, value);
    if(entry){
        entry->index = get_next_id(table);
        push_on_bucket(table, hashcode, entry);
        table->entry_count++;
    }
    return entry;
}

/** Move the front entry for a bucket to the correct point in the bucket order as
 * defined by the order function. If this is called every time a new entry is added
 * the bucket will be maintained in sorted order.
 *
 * @param table to modify
 * @param hashcode indicates the bucket
 * @param order entry comparison function
 * @return 0 if an entry was moved, 1 if not
 */
int HashTable_order_bucket(HashTable *table, Hashcode hashcode, TableOrderFn *order){
    HTEntry *new_entry = NULL, *prev = NULL, *entry = NULL;
    HTBucket *bucket;
    int err = 1;

    bucket = get_bucket(table, hashcode);
    new_entry = bucket->head;
    if(!new_entry || !new_entry->next) goto exit;
    for(entry = new_entry->next; entry; prev = entry, entry = entry->next){
        if(order(new_entry, entry) <= 0) break;
    }
    if(prev){
        err = 0;
        bucket->head = new_entry->next; 
        new_entry->next = entry;
        prev->next = new_entry;
    }
  exit:
    return err;
}

/** Add an entry to a hashtable.
 * The entry is added to the bucket for its key's hashcode.
 *
 * @param table to insert in
 * @param key to add an entry for
 * @param value to add an entry for
 * @return entry on success, 0 on failure
 */
inline HTEntry * HashTable_add(HashTable *table, void *key, void *value){
    return HashTable_add_entry(table, HashTable_key_hash(table, key), key, value);
}


/** Remove entries satisfying a test from the bucket for the
 * given hashcode. 
 *
 * @param table to remove from
 * @param hashcode indicates the bucket
 * @param test_fn test to apply to elements
 * @param arg first argument to calls to test_fn
 * @return number of entries removed
 */
inline int HashTable_remove_entry(HashTable *table, Hashcode hashcode,
				  TableTestFn *test_fn, TableArg arg){
    HTBucket *bucket;
    HTEntry *entry, *prev = 0, *next;
    int removed_count = 0;

    bucket = get_bucket(table, hashcode);
    for(entry = bucket->head; entry; entry = next){
        next = entry->next;
        if(test_fn(arg, table, entry)){
            if(prev){
                prev->next = next;
            } else {
                bucket->head = next;
            }
            bucket->count--;
            table->entry_count--;
            removed_count++;
            HashTable_free_entry(table, entry);
            entry = 0;
        }
        prev = entry;
    }
    return removed_count;
}

/** Remove entries with a given key. 
 *
 * @param table to remove from
 * @param key of entries to remove
 * @return number of entries removed
 */
inline int HashTable_remove(HashTable *table, void *key){
#if 1
    Hashcode hashcode;
    HTBucket *bucket;
    HTEntry *entry, *prev = 0, *next;
    int removed_count = 0;

    hashcode = HashTable_key_hash(table, key);
    bucket = get_bucket(table, hashcode);
    for(entry = bucket->head; entry; entry = next){
        next = entry->next;
        if(HashTable_key_equal(table, key, entry->key)){
            if(prev){
                prev->next = next;
            } else {
                bucket->head = next;
            }
            bucket->count--;
            table->entry_count--;
            removed_count++;
            HashTable_free_entry(table, entry);
            entry = 0;
        }
        prev = entry;
    }
    return removed_count;
#else
    return HashTable_remove_entry(table, HashTable_key_hash(table, key),
				  has_key, (TableArg){ ptr: key});
#endif
}

/** Remove (and free) all the entries in a bucket.
 *
 * @param bucket to clear
 */
static inline void bucket_clear(HashTable *table, HTBucket *bucket){
    HTEntry *entry, *next;

    for(entry = bucket->head; entry; entry = next){
        next = entry->next;
        HashTable_free_entry(table, entry);
    }
    bucket->head = 0;
    table->entry_count -= bucket->count;
    bucket->count = 0;
}

/** Remove (and free) all the entries in a table.
 *
 * @param table to clear
 */
void HashTable_clear(HashTable *table){
    int i, n = table->buckets_n;

    for(i=0; i<n; i++){
        bucket_clear(table, table->buckets + i);
    }
}
