/*
 * PCI Backend - Configuration space overlay for power management
 *
 * Author: Ryan Wilson <hap9@epoch.ncsc.mil>
 */

#include <linux/pci.h>
#include "conf_space.h"
#include "conf_space_capability.h"

static int pm_caps_read(struct pci_dev *dev, int offset, u16 *value,
			void *data)
{
	int err;
	u16 real_value;

	err = pci_read_config_word(dev, offset, &real_value);
	if (err)
		goto out;

	*value = real_value & ~PCI_PM_CAP_PME_MASK;

      out:
	return err;
}

/* PM_OK_BITS specifies the bits that the driver domain is allowed to change.
 * Can't allow driver domain to enable PMEs - they're shared */
#define PM_OK_BITS (PCI_PM_CTRL_PME_STATUS|PCI_PM_CTRL_DATA_SEL_MASK)

static int pm_ctrl_write(struct pci_dev *dev, int offset, u16 new_value,
			 void *data)
{
	int err;
	u16 old_value;
	pci_power_t new_state, old_state;

	err = pci_read_config_word(dev, offset, &old_value);
	if (err)
		goto out;

	old_state = (pci_power_t)(old_value & PCI_PM_CTRL_STATE_MASK);
	new_state = (pci_power_t)(new_value & PCI_PM_CTRL_STATE_MASK);

	new_value &= PM_OK_BITS;
	if ((old_value & PM_OK_BITS) != new_value) {
		new_value = (old_value & ~PM_OK_BITS) | new_value;
		err = pci_write_config_word(dev, offset, new_value);
		if (err)
			goto out;
	}

	/* Let pci core handle the power management change */
	dev_dbg(&dev->dev, "set power state to %x\n", new_state);
	err = pci_set_power_state(dev, new_state);
	if (err) {
		err = PCIBIOS_SET_FAILED;
		goto out;
	}

	/*
	 * Device may lose PCI config info on D3->D0 transition. This
	 * is a problem for some guests which will not reset BARs. Even
	 * those that have a go will be foiled by our BAR-write handler
	 * which will discard the write! Since Linux won't re-init
	 * the config space automatically in all cases, we do it here.
	 * Future: Should we re-initialise all first 64 bytes of config space?
	 */
	if (new_state == PCI_D0 &&
	    (old_state == PCI_D3hot || old_state == PCI_D3cold) &&
	    !(old_value & PCI_PM_CTRL_NO_SOFT_RESET))
		pci_restore_bars(dev);

 out:
	return err;
}

/* Ensure PMEs are disabled */
static void *pm_ctrl_init(struct pci_dev *dev, int offset)
{
	int err;
	u16 value;

	err = pci_read_config_word(dev, offset, &value);
	if (err)
		goto out;

	if (value & PCI_PM_CTRL_PME_ENABLE) {
		value &= ~PCI_PM_CTRL_PME_ENABLE;
		err = pci_write_config_word(dev, offset, value);
	}

      out:
	return ERR_PTR(err);
}

static struct config_field caplist_pm[] = {
	{
		.offset     = PCI_PM_PMC,
		.size       = 2,
		.u.w.read   = pm_caps_read,
	},
	{
		.offset     = PCI_PM_CTRL,
		.size       = 2,
		.init       = pm_ctrl_init,
		.u.w.read   = pciback_read_config_word,
		.u.w.write  = pm_ctrl_write,
	},
	{
		.offset     = PCI_PM_PPB_EXTENSIONS,
		.size       = 1,
		.u.b.read   = pciback_read_config_byte,
	},
	{
		.offset     = PCI_PM_DATA_REGISTER,
		.size       = 1,
		.u.b.read   = pciback_read_config_byte,
	},
	{
		.size = 0,
	},
};

struct pciback_config_capability pciback_config_capability_pm = {
	.capability = PCI_CAP_ID_PM,
	.fields = caplist_pm,
};
