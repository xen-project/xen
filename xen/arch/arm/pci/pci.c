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

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/param.h>
#include <xen/pci.h>

/*
 * PIRQ event channels are not supported on Arm, so nothing to do.
 */
int arch_pci_clean_pirqs(struct domain *d)
{
    return 0;
}

struct pci_dev *dev_to_pci(struct device *dev)
{
    ASSERT(dev->type == DEV_PCI);

    return container_of(dev, struct pci_dev, arch.dev);
}

void arch_pci_init_pdev(struct pci_dev *pdev)
{
    pci_to_dev(pdev)->type = DEV_PCI;
}

static int __init dt_pci_init(void)
{
    struct dt_device_node *np;
    int rc;

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_PCI_HOSTBRIDGE, NULL);
        /*
         * Ignore the following error codes:
         *   - EBADF: Indicate the current device is not a pci device.
         *   - ENODEV: The pci device is not present or cannot be used by
         *     Xen.
         */
        if( !rc || rc == -EBADF || rc == -ENODEV )
            continue;

        return rc;
    }

    return 0;
}

#ifdef CONFIG_ACPI
static int __init acpi_pci_init(void)
{
    printk(XENLOG_ERR "ACPI pci init not supported \n");
    return -EOPNOTSUPP;
}
#else
static int __init acpi_pci_init(void)
{
    return -EINVAL;
}
#endif

/* By default pci passthrough is disabled. */
bool __read_mostly pci_passthrough_enabled;
boolean_param("pci-passthrough", pci_passthrough_enabled);

static int __init pci_init(void)
{
    /*
     * Enable PCI passthrough when has been enabled explicitly
     * (pci-passthrough=on).
     */
    if ( !pci_passthrough_enabled )
        return 0;

    pci_segments_init();

    if ( acpi_disabled )
        return dt_pci_init();
    else
        return acpi_pci_init();
}
__initcall(pci_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
