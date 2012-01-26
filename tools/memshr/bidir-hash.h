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
#ifndef __BIDIR_HASH_H__
#define __BIDIR_HASH_H__

#include <stdint.h>
#include <string.h>
#include "memshr-priv.h"

typedef struct vbdblk {
    uint64_t sec;
    uint16_t disk_id;
} vbdblk_t;


#if defined FINGERPRINT_MAP || BLOCK_MAP 
#define DEFINE_SINGLE_MAP 
#endif

/*******************************************************/
/* Fingerprint map                                     */
/*******************************************************/
#if defined FINGERPRINT_MAP || !defined DEFINE_SINGLE_MAP

#undef BIDIR_NAME_PREFIX
#undef BIDIR_KEY
#undef BIDIR_VALUE
#undef BIDIR_KEY_T
#undef BIDIR_VALUE_T
static uint32_t fgprtshr_fgprt_hash(uint32_t h)
{
    return h;
}

static uint32_t fgprtshr_mfn_hash(uint64_t m)
{
    return (uint32_t)m;
}

static int fgprtshr_fgprt_cmp(uint32_t h1, uint32_t h2)
{
    return (h1 == h2);
}

static int fgprtshr_mfn_cmp(uint32_t m1, uint32_t m2)
{
    return (m1 == m2);
}
#define BIDIR_NAME_PREFIX       fgprtshr 
#define BIDIR_KEY               fgprt 
#define BIDIR_VALUE             mfn 
#define BIDIR_KEY_T             uint32_t
#define BIDIR_VALUE_T           xen_mfn_t
#include "bidir-namedefs.h"

#endif /* FINGERPRINT_MAP */


/*******************************************************/
/* Block<->Memory sharing handles                      */
/*******************************************************/
#if defined BLOCK_MAP || !defined DEFINE_SINGLE_MAP

#undef BIDIR_NAME_PREFIX
#undef BIDIR_KEY
#undef BIDIR_VALUE
#undef BIDIR_KEY_T
#undef BIDIR_VALUE_T

/* TODO better hashes! */
static inline uint32_t blockshr_block_hash(vbdblk_t block)
{
    return (uint32_t)(block.sec) ^ (uint32_t)(block.disk_id);
}

static inline uint32_t blockshr_shrhnd_hash(share_tuple_t shrhnd)
{
    return ((uint32_t) shrhnd.handle);
}

static inline int blockshr_block_cmp(vbdblk_t b1, vbdblk_t b2)
{
    return (b1.sec == b2.sec) && (b1.disk_id == b2.disk_id);
}

static inline int blockshr_shrhnd_cmp(share_tuple_t h1, share_tuple_t h2)
{
    return ( !memcmp(&h1, &h2, sizeof(share_tuple_t)) );
}
#define BIDIR_NAME_PREFIX       blockshr
#define BIDIR_KEY               block
#define BIDIR_VALUE             shrhnd
#define BIDIR_KEY_T             vbdblk_t
#define BIDIR_VALUE_T           share_tuple_t
#include "bidir-namedefs.h"

#endif /* BLOCK_MAP */

#endif /* __BIDIR_HASH_H__ */
