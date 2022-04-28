/*
 * Based on Linux drivers/pci/ecam.c
 *
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
#include <xen/sched.h>

/*
 * Function to implement the pci_ops->map_bus method.
 */
void __iomem *pci_ecam_map_bus(struct pci_host_bridge *bridge,
                               pci_sbdf_t sbdf, uint32_t where)
{
    const struct pci_config_window *cfg = bridge->cfg;
    const struct pci_ecam_ops *ops =
        container_of(bridge->ops, const struct pci_ecam_ops, pci_ops);
    unsigned int devfn_shift = ops->bus_shift - 8;
    void __iomem *base;
    unsigned int busn = sbdf.bus;

    if ( busn < cfg->busn_start || busn > cfg->busn_end )
        return NULL;

    busn -= cfg->busn_start;
    base = cfg->win + (busn << ops->bus_shift);

    return base + (sbdf.devfn << devfn_shift) + where;
}

bool __init pci_ecam_need_p2m_hwdom_mapping(struct domain *d,
                                            struct pci_host_bridge *bridge,
                                            uint64_t addr)
{
    struct pci_config_window *cfg = bridge->cfg;

    /*
     * We do not want ECAM address space to be mapped in Domain-0's p2m,
     * so we can trap access to it.
     */
    return cfg->phys_addr != addr;
}

/* ECAM ops */
const struct pci_ecam_ops pci_generic_ecam_ops = {
    .bus_shift  = 20,
    .pci_ops    = {
        .map_bus                = pci_ecam_map_bus,
        .read                   = pci_generic_config_read,
        .write                  = pci_generic_config_write,
        .need_p2m_hwdom_mapping = pci_ecam_need_p2m_hwdom_mapping,
    }
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
