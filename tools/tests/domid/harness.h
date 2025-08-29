/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit test harness for domain ID allocator.
 *
 * Copyright 2025 Ford Motor Company
 */

#ifndef _TEST_HARNESS_
#define _TEST_HARNESS_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <xen-tools/common-macros.h>
#include <xen-tools/bitops.h>

typedef bool spinlock_t;
typedef uint16_t domid_t;

extern domid_t domid_alloc(domid_t domid);
extern void domid_free(domid_t domid);

extern unsigned long find_next_zero_bit(const unsigned long *addr,
                                        unsigned long size,
                                        unsigned long offset);

#define __test_and_set_bit(nr, addr)    test_and_set_bit(nr, addr)
#define __test_and_clear_bit(nr, addr)  test_and_clear_bit(nr, addr)
#define __set_bit(nr, addr)             set_bit(nr, addr)

#define BUG_ON(x)                       assert(!(x))
#define ASSERT(x)                       assert(x)

#define DEFINE_SPINLOCK(l)              spinlock_t l
#define spin_lock(l)                    (assert(!*(l)), *(l) = true)
#define spin_unlock(l)                  (assert(*(l)), *(l) = false)

#define printk                          printf

#define DOMID_FIRST_RESERVED            (100)
#define DOMID_INVALID                   (101)

#endif /* _TEST_HARNESS_ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
