/* Copyright (C) 2002 Christopher Clark <firstname.lastname@cl.cam.ac.uk> */

#ifndef __HASHTABLE_CWC22_H__
#define __HASHTABLE_CWC22_H__

struct hashtable;

/*****************************************************************************
 * create_hashtable
   
 * @name                    create_hashtable
 * @param   ctx             talloc context to use for allocations
 * @param   name            talloc name of the hashtable
 * @param   hashfunction    function for hashing keys
 * @param   key_eq_fn       function for determining key equality
 * @param   flags           flags HASHTABLE_*
 * @return                  newly created hashtable or NULL on failure
 */

/* Let hashtable_destroy() free the entries' values. */
#define HASHTABLE_FREE_VALUE (1U << 0)
/* Let hashtable_remove() and hashtable_destroy() free the entries' keys. */
#define HASHTABLE_FREE_KEY   (1U << 1)

struct hashtable *
create_hashtable(const void *ctx, const char *name,
                 unsigned int (*hashfunction) (const void *),
                 int (*key_eq_fn) (const void *, const void *),
                 unsigned int flags
);

/*****************************************************************************
 * hashtable_add
   
 * @name        hashtable_add
 * @param   h   the hashtable to insert into
 * @param   k   the key - hashtable claims ownership and will free on removal
 * @param   v   the value - does not claim ownership
 * @return      zero for successful insertion
 *
 * This function will cause the table to expand if the insertion would take
 * the ratio of entries to table size over the maximum load factor.
 */

int
hashtable_add(struct hashtable *h, const void *k, void *v);

/*****************************************************************************
 * hashtable_replace

 * @name        hashtable_nsert
 * @param   h   the hashtable to insert into
 * @param   k   the key - hashtable claims ownership and will free on removal
 * @param   v   the value - does not claim ownership
 * @return      zero for successful insertion
 *
 * This function does check for an entry being present before replacing it
 * with a new value.
 */

int
hashtable_replace(struct hashtable *h, const void *k, void *v);

/*****************************************************************************
 * hashtable_search
   
 * @name        hashtable_search
 * @param   h   the hashtable to search
 * @param   k   the key to search for  - does not claim ownership
 * @return      the value associated with the key, or NULL if none found
 */

void *
hashtable_search(const struct hashtable *h, const void *k);

/*****************************************************************************
 * hashtable_remove
   
 * @name        hashtable_remove
 * @param   h   the hashtable to remove the item from
 * @param   k   the key to search for  - does not claim ownership
 */

void
hashtable_remove(struct hashtable *h, const void *k);

/*****************************************************************************
 * hashtable_iterate

 * @name           hashtable_iterate
 * @param   h      the hashtable
 * @param   func   function to call for each entry
 * @param   arg    user supplied parameter for func
 * @return         0 if okay, non-zero return value of func (and iteration
 *                 was aborted)
 *
 * Iterates over all entries in the hashtable and calls func with the
 * key, value, and the user supplied parameter.
 * func returning a non-zero value will abort the iteration. In case func is
 * removing an entry other than itself from the hashtable, it must return a
 * non-zero value in order to abort the iteration. Inserting entries is
 * allowed, but it is undefined whether func will be called for those new
 * entries during this iteration.
 */
int
hashtable_iterate(struct hashtable *h,
                  int (*func)(const void *k, void *v, void *arg), void *arg);

/*****************************************************************************
 * hashtable_destroy
   
 * @name        hashtable_destroy
 * @param   h   the hashtable
 */

void
hashtable_destroy(struct hashtable *h);

#endif /* __HASHTABLE_CWC22_H__ */

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
