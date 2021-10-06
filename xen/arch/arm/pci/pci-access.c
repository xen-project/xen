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

int pci_generic_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                            uint32_t reg, uint32_t len, uint32_t *value)
{
    void __iomem *addr = bridge->ops->map_bus(bridge, sbdf, reg);

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
    void __iomem *addr = bridge->ops->map_bus(bridge, sbdf, reg);

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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
