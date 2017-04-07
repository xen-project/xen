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

#define GITS_CTLR                       0x000
#define GITS_IIDR                       0x004
#define GITS_TYPER                      0x008
#define GITS_CBASER                     0x080
#define GITS_CWRITER                    0x088
#define GITS_CREADR                     0x090
#define GITS_BASER_NR_REGS              8
#define GITS_BASER0                     0x100
#define GITS_BASER1                     0x108
#define GITS_BASER2                     0x110
#define GITS_BASER3                     0x118
#define GITS_BASER4                     0x120
#define GITS_BASER5                     0x128
#define GITS_BASER6                     0x130
#define GITS_BASER7                     0x138

/* Register bits */
#define GITS_TYPER_DEVIDS_SHIFT         13
#define GITS_TYPER_DEVIDS_MASK          (0x1fUL << GITS_TYPER_DEVIDS_SHIFT)
#define GITS_TYPER_DEVICE_ID_BITS(r)    (((r & GITS_TYPER_DEVIDS_MASK) >> \
                                               GITS_TYPER_DEVIDS_SHIFT) + 1)

#define GITS_TYPER_IDBITS_SHIFT         8
#define GITS_TYPER_IDBITS_MASK          (0x1fUL << GITS_TYPER_IDBITS_SHIFT)
#define GITS_TYPER_EVENT_ID_BITS(r)     (((r & GITS_TYPER_IDBITS_MASK) >> \
                                               GITS_TYPER_IDBITS_SHIFT) + 1)

#define GITS_TYPER_ITT_SIZE_SHIFT       4
#define GITS_TYPER_ITT_SIZE_MASK        (0xfUL << GITS_TYPER_ITT_SIZE_SHIFT)
#define GITS_TYPER_ITT_SIZE(r)          ((((r) & GITS_TYPER_ITT_SIZE_MASK) >> \
                                                 GITS_TYPER_ITT_SIZE_SHIFT) + 1)

#include <xen/device_tree.h>

/* data structure for each hardware ITS */
struct host_its {
    struct list_head entry;
    const struct dt_device_node *dt_node;
    paddr_t addr;
    paddr_t size;
    void __iomem *its_base;
    unsigned int devid_bits;
    unsigned int evid_bits;
    unsigned int itte_size;
};


#ifdef CONFIG_HAS_ITS

extern struct list_head host_its_list;

/* Parse the host DT and pick up all host ITSes. */
void gicv3_its_dt_init(const struct dt_device_node *node);

bool gicv3_its_host_has_its(void);

int gicv3_lpi_init_rdist(void __iomem * rdist_base);

/* Initialize the host structures for LPIs and the host ITSes. */
int gicv3_lpi_init_host_lpis(unsigned int host_lpi_bits);
int gicv3_its_init(void);

#else

static inline void gicv3_its_dt_init(const struct dt_device_node *node)
{
}

static inline bool gicv3_its_host_has_its(void)
{
    return false;
}

static inline int gicv3_lpi_init_rdist(void __iomem * rdist_base)
{
    return -ENODEV;
}

static inline int gicv3_lpi_init_host_lpis(unsigned int host_lpi_bits)
{
    return 0;
}

static inline int gicv3_its_init(void)
{
    return 0;
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
