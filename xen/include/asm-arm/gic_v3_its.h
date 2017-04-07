/*
 * ARM GICv3 ITS support
 *
 * Andre Przywara <andre.przywara@arm.com>
 * Copyright (c) 2016,2017 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_ARM_ITS_H__
#define __ASM_ARM_ITS_H__

#include <xen/device_tree.h>

/* data structure for each hardware ITS */
struct host_its {
    struct list_head entry;
    const struct dt_device_node *dt_node;
    paddr_t addr;
    paddr_t size;
};


#ifdef CONFIG_HAS_ITS

extern struct list_head host_its_list;

/* Parse the host DT and pick up all host ITSes. */
void gicv3_its_dt_init(const struct dt_device_node *node);

bool gicv3_its_host_has_its(void);

#else

static inline void gicv3_its_dt_init(const struct dt_device_node *node)
{
}

static inline bool gicv3_its_host_has_its(void)
{
    return false;
}

#endif /* CONFIG_HAS_ITS */

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
