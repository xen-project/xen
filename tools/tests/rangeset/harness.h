/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for rangesets.
 *
 * Copyright (C) 2025 Cloud Software Group
 */

#ifndef _TEST_HARNESS_
#define _TEST_HARNESS_

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xen-tools/common-macros.h>

#define smp_wmb()
#define __must_check __attribute__((__warn_unused_result__))
#define cf_check

#define BUG_ON(x) assert(!(x))
#define ASSERT(x) assert(x)

#include "list.h"
#include "rangeset.h"

typedef bool rwlock_t;
typedef bool spinlock_t;

struct domain {
    unsigned int     domain_id;
    struct list_head rangesets;
    spinlock_t       rangesets_lock;
};

/* For rangeset_domain_{initialize,printk}() */
#define spin_lock_init(l) (*(l) = false)
#define spin_lock(l)      (*(l) = true)
#define spin_unlock(l)    (*(l) = false)

/* For rangeset->lock */
#define rwlock_init(l)    (*(l) = false)
#define read_lock(l)      (*(l) = true)
#define read_unlock(l)    (*(l) = false)
#define write_lock(l)     (*(l) = true)
#define write_unlock(l)   (*(l) = false)

#define xmalloc(type) ((type *)malloc(sizeof(type)))
#define xfree free

#define unlikely

#define safe_strcpy strcpy

#define printk printf

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
