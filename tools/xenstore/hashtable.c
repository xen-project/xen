/* Copyright (C) 2004 Christopher Clark <firstname.lastname@cl.cam.ac.uk> */

#include "hashtable.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stdarg.h>
#include "talloc.h"

struct entry
{
    void *k, *v;
    unsigned int h;
    struct entry *next;
};

struct hashtable {
    unsigned int tablelength;
    unsigned int flags;
    struct entry **table;
    unsigned int entrycount;
    unsigned int loadlimit;
    unsigned int primeindex;
    unsigned int (*hashfn) (const void *k);
    int (*eqfn) (const void *k1, const void *k2);
};

/*
 * Credit for primes table: Aaron Krowne
 * https://planetmath.org/goodhashtableprimes
 */
static const unsigned int primes[] = {
11, 23, 53, 97, 193, 389,
769, 1543, 3079, 6151,
12289, 24593, 49157, 98317,
196613, 393241, 786433, 1572869,
3145739, 6291469, 12582917, 25165843,
50331653, 100663319, 201326611, 402653189,
805306457, 1610612741
};
const unsigned int prime_table_length = sizeof(primes)/sizeof(primes[0]);
const unsigned int max_load_factor = 65; /* percentage */

/*****************************************************************************/
/* indexFor */
static inline unsigned int
indexFor(unsigned int tablelength, unsigned int hashvalue) {
    return (hashvalue % tablelength);
}

/*****************************************************************************/
struct hashtable *
create_hashtable(const void *ctx, unsigned int minsize,
                 unsigned int (*hashf) (const void *),
                 int (*eqf) (const void *, const void *),
                 unsigned int flags)
{
    struct hashtable *h;
    unsigned int pindex, size = primes[0];

    /* Check requested hashtable isn't too large */
    if (minsize > (1u << 30)) return NULL;

    /* Enforce size as prime */
    for (pindex=0; pindex < prime_table_length; pindex++) {
        if (primes[pindex] > minsize) { size = primes[pindex]; break; }
    }

    h = talloc_zero(ctx, struct hashtable);
    if (NULL == h)
        goto err0;
    h->table = talloc_zero_array(h, struct entry *, size);
    if (NULL == h->table)
        goto err1;

    h->tablelength  = size;
    h->flags        = flags;
    h->primeindex   = pindex;
    h->entrycount   = 0;
    h->hashfn       = hashf;
    h->eqfn         = eqf;
    h->loadlimit    = (unsigned int)(((uint64_t)size * max_load_factor) / 100);
    return h;

err1:
   talloc_free(h);
err0:
   return NULL;
}

/*****************************************************************************/
unsigned int
hash(const struct hashtable *h, const void *k)
{
    /* Aim to protect against poor hash functions by adding logic here
     * - logic taken from java 1.4 hashtable source */
    unsigned int i = h->hashfn(k);
    i += ~(i << 9);
    i ^=  ((i >> 14) | (i << 18)); /* >>> */
    i +=  (i << 4);
    i ^=  ((i >> 10) | (i << 22)); /* >>> */
    return i;
}

/*****************************************************************************/
static int
hashtable_expand(struct hashtable *h)
{
    /* Double the size of the table to accomodate more entries */
    struct entry **newtable;
    struct entry *e;
    struct entry **pE;
    unsigned int newsize, i, index;
    /* Check we're not hitting max capacity */
    if (h->primeindex == (prime_table_length - 1)) return 0;
    newsize = primes[++(h->primeindex)];

    newtable = talloc_realloc(h, h->table, struct entry *, newsize);
    if (!newtable)
    {
        h->primeindex--;
        return 0;
    }

    h->table = newtable;
    memset(newtable + h->tablelength, 0,
           (newsize - h->tablelength) * sizeof(*newtable));
    for (i = 0; i < h->tablelength; i++) {
        for (pE = &(newtable[i]), e = *pE; e != NULL; e = *pE) {
            index = indexFor(newsize, e->h);
            if (index == i)
            {
                pE = &(e->next);
            }
            else
            {
                *pE = e->next;
                e->next = newtable[index];
                newtable[index] = e;
            }
        }
    }

    h->tablelength = newsize;
    h->loadlimit   = (unsigned int)
        (((uint64_t)newsize * max_load_factor) / 100);
    return -1;
}

/*****************************************************************************/
unsigned int
hashtable_count(const struct hashtable *h)
{
    return h->entrycount;
}

/*****************************************************************************/
int
hashtable_insert(struct hashtable *h, void *k, void *v)
{
    /* This method allows duplicate keys - but they shouldn't be used */
    unsigned int index;
    struct entry *e;
    if (++(h->entrycount) > h->loadlimit)
    {
        /* Ignore the return value. If expand fails, we should
         * still try cramming just this value into the existing table
         * -- we may not have memory for a larger table, but one more
         * element may be ok. Next time we insert, we'll try expanding again.*/
        hashtable_expand(h);
    }
    e = talloc_zero(h, struct entry);
    if (NULL == e) { --(h->entrycount); return 0; } /*oom*/
    e->h = hash(h,k);
    index = indexFor(h->tablelength,e->h);
    e->k = k;
    if (h->flags & HASHTABLE_FREE_KEY)
        talloc_steal(e, k);
    e->v = v;
    if (h->flags & HASHTABLE_FREE_VALUE)
        talloc_steal(e, v);
    e->next = h->table[index];
    h->table[index] = e;
    return -1;
}

/*****************************************************************************/
void * /* returns value associated with key */
hashtable_search(const struct hashtable *h, const void *k)
{
    struct entry *e;
    unsigned int hashvalue, index;
    hashvalue = hash(h,k);
    index = indexFor(h->tablelength,hashvalue);
    e = h->table[index];
    while (NULL != e)
    {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k))) return e->v;
        e = e->next;
    }
    return NULL;
}

/*****************************************************************************/
void
hashtable_remove(struct hashtable *h, const void *k)
{
    /* TODO: consider compacting the table when the load factor drops enough,
     *       or provide a 'compact' method. */

    struct entry *e;
    struct entry **pE;
    unsigned int hashvalue, index;

    hashvalue = hash(h,k);
    index = indexFor(h->tablelength,hash(h,k));
    pE = &(h->table[index]);
    e = *pE;
    while (NULL != e)
    {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k)))
        {
            *pE = e->next;
            h->entrycount--;
            talloc_free(e);
            return;
        }
        pE = &(e->next);
        e = e->next;
    }
}

/*****************************************************************************/
int
hashtable_iterate(struct hashtable *h,
                  int (*func)(const void *k, void *v, void *arg), void *arg)
{
    int ret;
    unsigned int i;
    struct entry *e, *f;
    struct entry **table = h->table;

    for (i = 0; i < h->tablelength; i++)
    {
        e = table[i];
        while (e)
        {
            f = e;
            e = e->next;
            ret = func(f->k, f->v, arg);
            if (ret)
                return ret;
        }
    }

    return 0;
}

/*****************************************************************************/
/* destroy */
void
hashtable_destroy(struct hashtable *h)
{
    talloc_free(h);
}

/*
 * Copyright (c) 2002, Christopher Clark
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * * Neither the name of the original author; nor the names of any contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
