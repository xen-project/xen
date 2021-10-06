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
