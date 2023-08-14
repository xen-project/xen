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
    const void *k;
    void *v;
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

#define PRIME_TABLE_LEN   ARRAY_SIZE(primes)
#define MAX_LOAD_PERCENT  65

static inline unsigned int indexFor(unsigned int tablelength,
                                    unsigned int hashvalue)
{
    return (hashvalue % tablelength);
}

static unsigned int loadlimit(unsigned int pindex)
{
    return ((uint64_t)primes[pindex] * MAX_LOAD_PERCENT) / 100;
}

struct hashtable *create_hashtable(const void *ctx, const char *name,
                                   unsigned int (*hashf) (const void *),
                                   int (*eqf) (const void *, const void *),
                                   unsigned int flags)
{
    struct hashtable *h;

    h = talloc_zero(ctx, struct hashtable);
    if (NULL == h)
        goto err0;
    talloc_set_name_const(h, name);
    h->table = talloc_zero_array(h, struct entry *, primes[0]);
    if (NULL == h->table)
        goto err1;

    h->primeindex   = 0;
    h->tablelength  = primes[h->primeindex];
    h->flags        = flags;
    h->entrycount   = 0;
    h->hashfn       = hashf;
    h->eqfn         = eqf;
    h->loadlimit    = loadlimit(h->primeindex);
    return h;

err1:
   talloc_free(h);
err0:
   return NULL;
}

static unsigned int hash(const struct hashtable *h, const void *k)
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

static int hashtable_expand(struct hashtable *h)
{
    /* Double the size of the table to accomodate more entries */
    struct entry **newtable;
    struct entry *e;
    struct entry **pE;
    unsigned int newsize, i, index;
    /* Check we're not hitting max capacity */
    if (h->primeindex == (PRIME_TABLE_LEN - 1))
        return ENOSPC;
    newsize = primes[++(h->primeindex)];

    newtable = talloc_realloc(h, h->table, struct entry *, newsize);
    if (!newtable)
    {
        h->primeindex--;
        return ENOMEM;
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
    h->loadlimit   = loadlimit(h->primeindex);
    return 0;
}

static struct entry *hashtable_search_entry(const struct hashtable *h,
                                            const void *k)
{
    struct entry *e;
    unsigned int hashvalue, index;

    hashvalue = hash(h, k);
    index = indexFor(h->tablelength, hashvalue);
    e = h->table[index];

    for (e = h->table[index]; e; e = e->next)
    {
        /* Check hash value to short circuit heavier comparison */
        if ((hashvalue == e->h) && (h->eqfn(k, e->k)))
            return e;
    }

    return NULL;
}

int hashtable_add(struct hashtable *h, const void *k, void *v)
{
    unsigned int index;
    struct entry *e;

    if (hashtable_search_entry(h, k))
        return EEXIST;

    if (++(h->entrycount) > h->loadlimit)
    {
        /* Ignore the return value. If expand fails, we should
         * still try cramming just this value into the existing table
         * -- we may not have memory for a larger table, but one more
         * element may be ok. Next time we insert, we'll try expanding again.*/
        hashtable_expand(h);
    }
    e = talloc_zero(h, struct entry);
    if (NULL == e)
    {
        --h->entrycount;
       return ENOMEM;
    }
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
    return 0;
}

void *hashtable_search(const struct hashtable *h, const void *k)
{
    struct entry *e;

    e = hashtable_search_entry(h, k);

    return e ? e->v : NULL;
}

int hashtable_replace(struct hashtable *h, const void *k, void *v)
{
    struct entry *e;

    e = hashtable_search_entry(h, k);
    if (!e)
        return ENOENT;

    if (h->flags & HASHTABLE_FREE_VALUE)
    {
        talloc_free(e->v);
        talloc_steal(e, v);
    }

    e->v = v;

    return 0;
}

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

int hashtable_iterate(struct hashtable *h,
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

void hashtable_destroy(struct hashtable *h)
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
