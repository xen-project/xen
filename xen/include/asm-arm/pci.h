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

#ifndef __ARM_PCI_H__
#define __ARM_PCI_H__

#ifdef CONFIG_HAS_PCI

#define pci_to_dev(pcidev) (&(pcidev)->arch.dev)

extern bool pci_passthrough_enabled;

/* Arch pci dev struct */
struct arch_pci_dev {
    struct device dev;
};

/*
 * struct to hold the mappings of a config space window. This
 * is expected to be used as sysdata for PCI controllers that
 * use ECAM.
 */
struct pci_config_window {
    paddr_t         phys_addr;
    paddr_t         size;
    uint8_t         busn_start;
    uint8_t         busn_end;
    void __iomem    *win;
};

/*
 * struct to hold pci host bridge information
 * for a PCI controller.
 */
struct pci_host_bridge {
    struct dt_device_node *dt_node;  /* Pointer to the associated DT node */
    struct list_head node;           /* Node in list of host bridges */
    uint16_t segment;                /* Segment number */
    struct pci_config_window* cfg;   /* Pointer to the bridge config window */
    struct pci_ops *ops;
};

struct pci_ops {
    void __iomem *(*map_bus)(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                             uint32_t offset);
    int (*read)(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                uint32_t reg, uint32_t len, uint32_t *value);
    int (*write)(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                 uint32_t reg, uint32_t len, uint32_t value);
};

/*
 * struct to hold pci ops and bus shift of the config window
 * for a PCI controller.
 */
struct pci_ecam_ops {
    unsigned int            bus_shift;
    struct pci_ops          pci_ops;
    int (*cfg_reg_index)(struct dt_device_node *dev);
    int (*init)(struct pci_config_window *);
};

/* Default ECAM ops */
extern const struct pci_ecam_ops pci_generic_ecam_ops;

int pci_host_common_probe(struct dt_device_node *dev, const void *data);
int pci_generic_config_read(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                            uint32_t reg, uint32_t len, uint32_t *value);
int pci_generic_config_write(struct pci_host_bridge *bridge, pci_sbdf_t sbdf,
                             uint32_t reg, uint32_t len, uint32_t value);
void __iomem *pci_ecam_map_bus(struct pci_host_bridge *bridge,
                               pci_sbdf_t sbdf, uint32_t where);

static always_inline bool is_pci_passthrough_enabled(void)
{
    return pci_passthrough_enabled;
}
#else   /*!CONFIG_HAS_PCI*/

struct arch_pci_dev { };

static always_inline bool is_pci_passthrough_enabled(void)
{
    return false;
}

#endif  /*!CONFIG_HAS_PCI*/
#endif /* __ARM_PCI_H__ */
