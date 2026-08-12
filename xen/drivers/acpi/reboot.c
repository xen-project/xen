#include <xen/pci.h>
#include <xen/acpi.h>
#include <acpi/acpi.h>

void acpi_reboot(void)
{
	struct acpi_generic_address *rr;
	u8 reset_value;
	pci_sbdf_t sbdf;

	rr = &acpi_gbl_FADT.reset_register;

	/* Is the reset register supported? The spec says we should be
	 * checking the bit width and bit offset, but Windows ignores
	 * these fields */
	if (!(acpi_gbl_FADT.flags & ACPI_FADT_RESET_REGISTER))
		return;

	reset_value = acpi_gbl_FADT.reset_value;

	/* The reset register can only exist in I/O, Memory or PCI config space
	 * on a device on bus 0. */
	switch (rr->space_id) {
	case ACPI_ADR_SPACE_PCI_CONFIG:
		sbdf = PCI_SBDF(0, 0, rr->address >> 32, rr->address >> 16);
		printk("Resetting with ACPI PCI %pp RESET_REG at %#"PRIx64" (%#x)\n",
		       &sbdf, rr->address & 0xff, reset_value);
		/* Write the value that resets us. */
		pci_conf_write8(sbdf, rr->address & 0xff, reset_value);
		break;

	case ACPI_ADR_SPACE_SYSTEM_MEMORY:
		printk("Resetting with ACPI MEMORY at %#"PRIx64" (%#x)\n",
		       rr->address, reset_value);
		acpi_hw_low_level_write(8, reset_value, rr);
		break;

	case ACPI_ADR_SPACE_SYSTEM_IO:
		printk("Resetting with I/O RESET_REG at %#"PRIx64" (%#x)\n",
		       rr->address, reset_value);
		acpi_hw_low_level_write(8, reset_value, rr);
		break;

	default:
		/* Fallback to alternative reboot methods */
		break;
	}
}
