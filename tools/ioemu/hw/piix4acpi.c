/*
 * PIIX4 ACPI controller emulation
 *
 * Winston liwen Wang, winston.l.wang@intel.com
 * Copyright (c) 2006 , Intel Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "vl.h"

/* PM1a_CNT bits, as defined in the ACPI specification. */
#define SCI_EN            (1 <<  0)
#define GBL_RLS           (1 <<  2)
#define SLP_TYP_Sx        (7 << 10)
#define SLP_EN            (1 << 13)

/* Sleep state type codes as defined by the \_Sx objects in the DSDT. */
/* These must be kept in sync with the DSDT (hvmloader/acpi/dsdt.asl) */
#define SLP_TYP_S5        (7 << 10)

typedef struct AcpiDeviceState AcpiDeviceState;
AcpiDeviceState *acpi_device_table;

typedef struct PCIAcpiState {
    PCIDevice dev;
    uint16_t pm1_control; /* pm1a_ECNT_BLK */
} PCIAcpiState;

static void piix4acpi_save(QEMUFile *f, void *opaque)
{
    PCIAcpiState *s = opaque;
    pci_device_save(&s->dev, f);
    qemu_put_be16s(f, &s->pm1_control);
}

static int piix4acpi_load(QEMUFile *f, void *opaque, int version_id)
{
    PCIAcpiState *s = opaque;
    int ret;
    if (version_id > 1) 
        return -EINVAL;
    ret = pci_device_load(&s->dev, f);
    if (ret < 0)
	return ret;
    qemu_get_be16s(f, &s->pm1_control);
    return 0;
}

static void acpiPm1Control_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;
    s->pm1_control = (s->pm1_control & 0xff00) | (val & 0xff);
}

static uint32_t acpiPm1Control_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    /* Mask out the write-only bits */
    return (uint8_t)(s->pm1_control & ~(GBL_RLS|SLP_EN));
}

static void acpiPm1ControlP1_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    val <<= 8;
    s->pm1_control = ((s->pm1_control & 0xff) | val) & ~SLP_EN;

    /* Check for power off request. */
    if ((val & (SLP_EN|SLP_TYP_Sx)) == (SLP_EN|SLP_TYP_S5))
        qemu_system_shutdown_request();
}

static uint32_t acpiPm1ControlP1_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    /* Mask out the write-only bits */
    return (uint8_t)((s->pm1_control & ~(GBL_RLS|SLP_EN)) >> 8);
}

static void acpiPm1Control_writew(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_control = val & ~SLP_EN;

    /* Check for power off request. */
    if ((val & (SLP_EN|SLP_TYP_Sx)) == (SLP_EN|SLP_TYP_S5))
        qemu_system_shutdown_request();
}

static uint32_t acpiPm1Control_readw(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    /* Mask out the write-only bits */
    return (s->pm1_control & ~(GBL_RLS|SLP_EN));
}

static void acpi_map(PCIDevice *pci_dev, int region_num,
                    uint32_t addr, uint32_t size, int type)
{
    PCIAcpiState *d = (PCIAcpiState *)pci_dev;

    /* Byte access */
    register_ioport_write(addr + 4, 1, 1, acpiPm1Control_writeb, d);
    register_ioport_read(addr + 4, 1, 1, acpiPm1Control_readb, d);
    register_ioport_write(addr + 4 + 1, 1, 1, acpiPm1ControlP1_writeb, d);
    register_ioport_read(addr + 4 +1, 1, 1, acpiPm1ControlP1_readb, d);

    /* Word access */
    register_ioport_write(addr + 4, 2, 2, acpiPm1Control_writew, d);
    register_ioport_read(addr + 4, 2, 2, acpiPm1Control_readw, d);
}

/* PIIX4 acpi pci configuration space, func 2 */
void pci_piix4_acpi_init(PCIBus *bus, int devfn)
{
    PCIAcpiState *d;
    uint8_t *pci_conf;

    /* register a function 2 of PIIX4 */
    d = (PCIAcpiState *)pci_register_device(
        bus, "PIIX4 ACPI", sizeof(PCIAcpiState),
        devfn, NULL, NULL);

    pci_conf = d->dev.config;
    pci_conf[0x00] = 0x86;  /* Intel */
    pci_conf[0x01] = 0x80;
    pci_conf[0x02] = 0x13;
    pci_conf[0x03] = 0x71;
    pci_conf[0x08] = 0x01;  /* B0 stepping */
    pci_conf[0x09] = 0x00;  /* base class */
    pci_conf[0x0a] = 0x80;  /* Sub class */
    pci_conf[0x0b] = 0x06;
    pci_conf[0x0e] = 0x00;
    pci_conf[0x3d] = 0x01;  /* Hardwired to PIRQA is used */


    /* PMBA POWER MANAGEMENT BASE ADDRESS, hardcoded to 0x1f40 
     * to make shutdown work for IPF, due to IPF Guest Firmware 
     * will enumerate pci devices. 
     *
     * TODO:  if Guest Firmware or Guest OS will change this PMBA,
     * More logic will be added.
     */
    pci_conf[0x40] = 0x41; /* Special device-specific BAR at 0x40 */
    pci_conf[0x41] = 0x1f;
    pci_conf[0x42] = 0x00;
    pci_conf[0x43] = 0x00;
    d->pm1_control = SCI_EN;

    acpi_map((PCIDevice *)d, 0, 0x1f40, 0x10, PCI_ADDRESS_SPACE_IO);

    register_savevm("piix4acpi", 0, 1, piix4acpi_save, piix4acpi_load, d);
}
