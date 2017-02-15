#include <xen/pci.h>
#include <xen/acpi.h>
#include <acpi/acpi.h>

void acpi_reboot(void)
{
	struct acpi_generic_address *rr;
	u8 reset_value;

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
		printk("Resetting with ACPI PCI RESET_REG.\n");
		/* Write the value that resets us. */
		pci_conf_write8(0, 0,
				(rr->address >> 32) & 31,
				(rr->address >> 16) & 7,
				(rr->address & 255),
				reset_value);
		break;
	case ACPI_ADR_SPACE_SYSTEM_MEMORY:
	case ACPI_ADR_SPACE_SYSTEM_IO:
		printk("Resetting with ACPI MEMORY or I/O RESET_REG.\n");
		acpi_hw_low_level_write(8, reset_value, rr);
		break;
	}
}
