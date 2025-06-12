/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/pci.h>
#include <asm/io.h>

#define INVALID_VALUE (~0U)
#define PCI_ERR_VALUE(len) GENMASK(0, len * 8)

static const struct pci_ops *get_ops(struct pci_host_bridge *bridge,
                                     pci_sbdf_t sbdf)
{
    if ( bridge->child_ops )
    {
        struct pci_config_window *cfg = bridge->child_cfg;

        if ( (sbdf.bus >= cfg->busn_start) && (sbdf.bus <= cfg->busn_end) )
            return bridge->child_ops;
    }
    return bridge->ops;
}

static inline void __iomem *map_bus(struct pci_host_bridge *bridge,
                                    pci_sbdf_t sbdf, uint32_t reg)
{
    const struct pci_ops *ops = get_ops(bridge, sbdf);

    return ops->map_bus(bridge, sbdf, reg);
}

int pci_generic_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                            uint32_t reg, uint32_t len, uint32_t *value)
{
    void __iomem *addr = map_bus(bridge, sbdf, reg);

    if ( !addr )
    {
        *value = INVALID_VALUE;
        return -ENODEV;
    }

    switch ( len )
    {
    case 1:
        *value = readb(addr);
        break;
    case 2:
        *value = readw(addr);
        break;
    case 4:
        *value = readl(addr);
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return 0;
}

int pci_generic_config_write(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                             uint32_t reg, uint32_t len, uint32_t value)
{
    void __iomem *addr = map_bus(bridge, sbdf, reg);

    if ( !addr )
        return -ENODEV;

    switch ( len )
    {
    case 1:
        writeb(value, addr);
        break;
    case 2:
        writew(value, addr);
        break;
    case 4:
        writel(value, addr);
        break;
    default:
        ASSERT_UNREACHABLE();
    }

    return 0;
}

static uint32_t pci_config_read(pci_sbdf_t sbdf, unsigned int reg,
                                unsigned int len)
{
    uint32_t val = PCI_ERR_VALUE(len);
    struct pci_host_bridge *bridge = pci_find_host_bridge(sbdf.seg, sbdf.bus);
    const struct pci_ops *ops;

    if ( unlikely(!bridge) )
        return val;

    ops = get_ops(bridge, sbdf);
    if ( unlikely(!ops->read) )
        return val;

    ops->read(bridge, sbdf, reg, len, &val);

    return val;
}

static void pci_config_write(pci_sbdf_t sbdf, unsigned int reg,
                             unsigned int len, uint32_t val)
{
    struct pci_host_bridge *bridge = pci_find_host_bridge(sbdf.seg, sbdf.bus);
    const struct pci_ops *ops;

    if ( unlikely(!bridge) )
        return;

    ops = get_ops(bridge, sbdf);
    if ( unlikely(!ops->write) )
        return;

    ops->write(bridge, sbdf, reg, len, val);
}

/*
 * Wrappers for all PCI configuration access functions.
 */

#define PCI_OP_WRITE(size, type)                            \
    void pci_conf_write##size(pci_sbdf_t sbdf,              \
                              unsigned int reg, type val)   \
{                                                           \
    pci_config_write(sbdf, reg, size / 8, val);             \
}

#define PCI_OP_READ(size, type)                             \
    type pci_conf_read##size(pci_sbdf_t sbdf,               \
                              unsigned int reg)             \
{                                                           \
    return pci_config_read(sbdf, reg, size / 8);            \
}

PCI_OP_READ(8, uint8_t)
PCI_OP_READ(16, uint16_t)
PCI_OP_READ(32, uint32_t)
PCI_OP_WRITE(8, uint8_t)
PCI_OP_WRITE(16, uint16_t)
PCI_OP_WRITE(32, uint32_t)

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
