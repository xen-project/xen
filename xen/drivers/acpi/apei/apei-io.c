/*
 * apei-io.c - APEI IO memory pre-mapping/post-unmapping and access
 *
 * Copyright (C) 2009-2010, Intel Corp.
 *	Author: Huang Ying <ying.huang@intel.com>
 *	Ported by: Liu, Jinsong <jinsong.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/kernel.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/string.h>
#include <xen/xmalloc.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/list.h>
#include <xen/cper.h>
#include <xen/prefetch.h>
#include <asm/fixmap.h>
#include <asm/io.h>
#include <acpi/acpi.h>
#include <acpi/apei.h>

static LIST_HEAD(apei_iomaps);
/*
 * Used for mutual exclusion between writers of apei_iomaps list, for
 * synchronization between readers and writer.
 */
static DEFINE_SPINLOCK(apei_iomaps_lock);

struct apei_iomap {
	struct list_head list;
	void __iomem *vaddr;
	unsigned long size;
	paddr_t paddr;
};

static struct apei_iomap *__apei_find_iomap(paddr_t paddr,
					    unsigned long size)
{
	struct apei_iomap *map;

	list_for_each_entry(map, &apei_iomaps, list) {
		if (map->paddr + map->size >= paddr + size &&
		    map->paddr <= paddr)
			return map;
	}
	return NULL;
}

static void __iomem *__apei_ioremap_fast(paddr_t paddr,
					 unsigned long size)
{
	struct apei_iomap *map;

	map = __apei_find_iomap(paddr, size);
	if (map)
		return map->vaddr + (paddr - map->paddr);
	else
		return NULL;
}

static int apei_range_nr;

static void __iomem *__init apei_range_map(paddr_t paddr, unsigned long size)
{
	int i, pg;
	int start_nr, cur_nr;

	pg = ((((paddr + size -1) & PAGE_MASK)
		 - (paddr & PAGE_MASK)) >> PAGE_SHIFT) + 1;
	if (apei_range_nr + pg > FIX_APEI_RANGE_MAX)
		return NULL;

	start_nr = apei_range_nr + pg -1;
	for (i = 0; i < pg; i++) {
		cur_nr = start_nr - i;
		set_fixmap_nocache(FIX_APEI_RANGE_BASE + cur_nr,
					paddr + (i << PAGE_SHIFT));
		apei_range_nr++;
	}

	return (void __iomem *)fix_to_virt(FIX_APEI_RANGE_BASE + start_nr);
}

/*
 * Used to pre-map the specified IO memory area. First try to find
 * whether the area is already pre-mapped, if it is, return; otherwise,
 * do the real map, and add the mapping into apei_iomaps list.
 */
void __iomem *__init apei_pre_map(paddr_t paddr, unsigned long size)
{
	void __iomem *vaddr;
	struct apei_iomap *map;
	unsigned long flags;

	spin_lock_irqsave(&apei_iomaps_lock, flags);
	vaddr = __apei_ioremap_fast(paddr, size);
	spin_unlock_irqrestore(&apei_iomaps_lock, flags);
	if (vaddr)
		return vaddr;

	map = xmalloc(struct apei_iomap);
	if (!map)
		return NULL;

	vaddr = apei_range_map(paddr, size);
	if (!vaddr) {
		xfree(map);
		return NULL;
	}

	INIT_LIST_HEAD(&map->list);
	map->paddr = paddr & PAGE_MASK;
	map->size = (((paddr + size + PAGE_SIZE -1) & PAGE_MASK)
					 - (paddr & PAGE_MASK));
	map->vaddr = vaddr;

	spin_lock_irqsave(&apei_iomaps_lock, flags);
	list_add_tail(&map->list, &apei_iomaps);
	spin_unlock_irqrestore(&apei_iomaps_lock, flags);

	return map->vaddr + (paddr - map->paddr);
}

/*
 * Used to post-unmap the specified IO memory area.
 */
static void __init apei_post_unmap(paddr_t paddr, unsigned long size)
{
	struct apei_iomap *map;
	unsigned long flags;

	spin_lock_irqsave(&apei_iomaps_lock, flags);
	map = __apei_find_iomap(paddr, size);
	if (map)
		list_del(&map->list);
	spin_unlock_irqrestore(&apei_iomaps_lock, flags);

	xfree(map);
}

/* In NMI handler, should set silent = 1 */
static int apei_check_gar(struct acpi_generic_address *reg,
			  u64 *paddr, int silent)
{
	u32 width, space_id;

	width = reg->bit_width;
	space_id = reg->space_id;
	/* Handle possible alignment issues */
	memcpy(paddr, &reg->address, sizeof(*paddr));
	if (!*paddr) {
		if (!silent)
			printk(KERN_WARNING
			"Invalid physical address in GAR\n");
		return -EINVAL;
	}

	if ((width != 8) && (width != 16) && (width != 32) && (width != 64)) {
		if (!silent)
			printk(KERN_WARNING
			"Invalid bit width in GAR\n");
		return -EINVAL;
	}

	if (space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY &&
	    space_id != ACPI_ADR_SPACE_SYSTEM_IO) {
		if (!silent)
			printk(KERN_WARNING
			"Invalid address space type in GAR\n");
		return -EINVAL;
	}

	return 0;
}

/* Pre-map, working on GAR */
int __init apei_pre_map_gar(struct acpi_generic_address *reg)
{
	u64 paddr;
	void __iomem *vaddr;
	int rc;

	if (reg->space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY)
		return 0;

	rc = apei_check_gar(reg, &paddr, 0);
	if (rc)
		return rc;

	vaddr = apei_pre_map(paddr, reg->bit_width / 8);
	if (!vaddr)
		return -EIO;

	return 0;
}

/* Post-unmap, working on GAR */
int __init apei_post_unmap_gar(struct acpi_generic_address *reg)
{
	u64 paddr;
	int rc;

	if (reg->space_id != ACPI_ADR_SPACE_SYSTEM_MEMORY)
		return 0;

	rc = apei_check_gar(reg, &paddr, 0);
	if (rc)
		return rc;

	apei_post_unmap(paddr, reg->bit_width / 8);

	return 0;
}

static int apei_read_mem(u64 paddr, u64 *val, u32 width)
{
	void __iomem *addr;
	u64 tmpval;

	addr = __apei_ioremap_fast(paddr, width);
	switch (width) {
	case 8:
		*val = readb(addr);
		break;
	case 16:
		*val = readw(addr);
		break;
	case 32:
		*val = readl(addr);
		break;
	case 64:
		tmpval = (u64)readl(addr);
		tmpval |= ((u64)readl(addr+4)) << 32;
		*val = tmpval;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int apei_write_mem(u64 paddr, u64 val, u32 width)
{
	void __iomem *addr;
	u32 tmpval;

	addr = __apei_ioremap_fast(paddr, width);
	switch (width) {
	case 8:
		writeb(val, addr);
		break;
	case 16:
		writew(val, addr);
		break;
	case 32:
		writel(val, addr);
		break;
	case 64:
		tmpval = (u32)val;
		writel(tmpval, addr);
		tmpval = (u32)(val >> 32);
		writel(tmpval, addr+4);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int apei_read(u64 *val, struct acpi_generic_address *reg)
{
	u64 paddr;
	int rc;

	rc = apei_check_gar(reg, &paddr, 1);
	if (rc)
		return rc;

	*val = 0;

	/* currently all erst implementation take bit_width as real range */
	switch (reg->space_id) {
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:
		return apei_read_mem(paddr, val, reg->bit_width);
	case ACPI_ADR_SPACE_SYSTEM_IO:
		return acpi_os_read_port(paddr, (u32 *)val, reg->bit_width);
	default:
		return -EINVAL;
	}
}

int apei_write(u64 val, struct acpi_generic_address *reg)
{
	u64 paddr;
	int rc;

	rc = apei_check_gar(reg, &paddr, 1);
	if (rc)
		return rc;

	switch (reg->space_id) {
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:
		return apei_write_mem(paddr, val, reg->bit_width);
	case ACPI_ADR_SPACE_SYSTEM_IO:
		return acpi_os_write_port(paddr, val, reg->bit_width);
	default:
		return -EINVAL;
	}
}
