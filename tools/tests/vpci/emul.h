/*
 * Unit tests for the generic vPCI handler code.
 *
 * Copyright (C) 2017 Citrix Systems R&D
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TEST_VPCI_
#define _TEST_VPCI_

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define container_of(ptr, type, member) ({                      \
        typeof(((type *)0)->member) *mptr = (ptr);              \
                                                                \
        (type *)((char *)mptr - offsetof(type, member));        \
})

#define smp_wmb()
#define prefetch(x) __builtin_prefetch(x)
#define ASSERT(x) assert(x)
#define __must_check __attribute__((__warn_unused_result__))

#include "list.h"

struct domain {
};

struct pci_dev {
    struct vpci *vpci;
};

struct vcpu
{
    const struct domain *domain;
};

extern const struct vcpu *current;
extern const struct pci_dev test_pdev;

typedef bool spinlock_t;
#define spin_lock_init(l) (*(l) = false)
#define spin_lock(l) (*(l) = true)
#define spin_unlock(l) (*(l) = false)

typedef union {
    uint32_t sbdf;
    struct {
        union {
            uint16_t bdf;
            struct {
                union {
                    struct {
                        uint8_t func : 3,
                                dev  : 5;
                    };
                    uint8_t     extfunc;
                };
                uint8_t         bus;
            };
        };
        uint16_t                seg;
    };
} pci_sbdf_t;

#define CONFIG_HAS_VPCI
#include "vpci.h"

#define __hwdom_init

#define has_vpci(d) true

#define xzalloc(type) ((type *)calloc(1, sizeof(type)))
#define xmalloc(type) ((type *)malloc(sizeof(type)))
#define xfree(p) free(p)

#define pci_get_pdev_by_domain(...) &test_pdev
#define pci_get_ro_map(...) NULL

#define test_bit(...) false

/* Dummy native helpers. Writes are ignored, reads return 1's. */
#define pci_conf_read8(...)     0xff
#define pci_conf_read16(...)    0xffff
#define pci_conf_read32(...)    0xffffffff
#define pci_conf_write8(...)
#define pci_conf_write16(...)
#define pci_conf_write32(...)

#define PCI_CFG_SPACE_EXP_SIZE 4096

#define BUG() assert(0)
#define ASSERT_UNREACHABLE() assert(0)

#define min(x, y) ({                    \
        const typeof(x) tx = (x);       \
        const typeof(y) ty = (y);       \
                                        \
        (void) (&tx == &ty);            \
        tx < ty ? tx : ty;              \
})

#define max(x, y) ({                    \
        const typeof(x) tx = (x);       \
        const typeof(y) ty = (y);       \
                                        \
        (void) (&tx == &ty);            \
        tx > ty ? tx : ty;              \
})

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
