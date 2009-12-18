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
#include "memshr-priv.h"

/* Macros used to assemble the names */
#define BIDIR_NAME_ONE_INTERNAL(prefix, name) \
                                prefix ## _ ## name
#define BIDIR_NAME_TWO_INTERNAL(prefix, name1, name2) \
                                prefix ## _ ## name1 ## _ ## name2

#define BIDIR_NAME_ONE(prefix, name) \
                                BIDIR_NAME_ONE_INTERNAL(prefix, name)
#define BIDIR_NAME_TWO(prefix, name1, name2) \
                                BIDIR_NAME_TWO_INTERNAL(prefix, name1, name2)

#define INTERNAL_NAME_ONE(name) BIDIR_NAME_ONE(BIDIR_NAME_PREFIX, name)
#define INTERNAL_NAME_TWO(name1, name2) \
                                BIDIR_NAME_TWO(BIDIR_NAME_PREFIX, name1, name2)

/* Function/type names */
#define __k_t                   BIDIR_KEY_T
#define __v_t                   BIDIR_VALUE_T

#define __hash                  INTERNAL_NAME_ONE(hash)
#define __shm_hash_init         INTERNAL_NAME_ONE(shm_hash_init)
#define __shm_hash_get          INTERNAL_NAME_ONE(shm_hash_get)
#define __hash_init             INTERNAL_NAME_ONE(hash_init)
#define __key_lookup            INTERNAL_NAME_TWO(BIDIR_KEY, lookup)
#define __value_lookup          INTERNAL_NAME_TWO(BIDIR_VALUE, lookup)
#define __insert                INTERNAL_NAME_ONE(insert)
#define __key_remove            INTERNAL_NAME_TWO(BIDIR_KEY, remove)
#define __value_remove          INTERNAL_NAME_TWO(BIDIR_VALUE, remove)
#define __hash_destroy          INTERNAL_NAME_ONE(hash_destroy)
#define __hash_iterator         INTERNAL_NAME_ONE(hash_iterator)

#define __key_hash              INTERNAL_NAME_TWO(BIDIR_KEY, hash)
#define __key_cmp               INTERNAL_NAME_TWO(BIDIR_KEY, cmp)
#define __value_hash            INTERNAL_NAME_TWO(BIDIR_VALUE, hash)
#define __value_cmp             INTERNAL_NAME_TWO(BIDIR_VALUE, cmp)

#define __hash_sizes            INTERNAL_NAME_ONE(hash_sizes)


/* Final function exports */
struct __hash* __shm_hash_init(unsigned long shm_baddr, unsigned long shm_size);
struct __hash* __shm_hash_get(unsigned long shm_baddr);
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
void           __hash_sizes(struct __hash *h,
                            uint32_t *nr_ent,
                            uint32_t *max_nr_ent,
                            uint32_t *tab_size,
                            uint32_t *max_load,
                            uint32_t *min_load);
