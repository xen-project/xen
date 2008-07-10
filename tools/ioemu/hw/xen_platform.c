/*
 * XEN platform fake pci device, formerly known as the event channel device
 * 
 * Copyright (c) 2003-2004 Intel Corp.
 * Copyright (c) 2006 XenSource
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

#include <xenguest.h>

extern FILE *logfile;

#define PFFLAG_ROM_LOCK 1 /* Sets whether ROM memory area is RW or RO */

typedef struct PCIXenPlatformState
{
  PCIDevice  pci_dev;
  uint8_t    platform_flags;
} PCIXenPlatformState;

static uint32_t xen_platform_ioport_readb(void *opaque, uint32_t addr)
{
    PCIXenPlatformState *s = opaque;

    addr &= 0xff;

    return (addr == 0) ? s->platform_flags : ~0u;
}
                              
static void xen_platform_ioport_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIXenPlatformState *d = opaque;

    addr &= 0xff;
    val  &= 0xff;

    switch (addr) {
    case 0: /* Platform flags */ {
        hvmmem_type_t mem_type = (val & PFFLAG_ROM_LOCK) ?
            HVMMEM_ram_ro : HVMMEM_ram_rw;
        if (xc_hvm_set_mem_type(xc_handle, domid, mem_type, 0xc0, 0x40))
            fprintf(logfile,"xen_platform: unable to change ro/rw "
                    "state of ROM memory area!\n");
        else
            d->platform_flags = val & PFFLAG_ROM_LOCK;
        break;
    }
    default:
        break;
    }
}


static void platform_ioport_map(PCIDevice *pci_dev, int region_num, uint32_t addr, uint32_t size, int type)
{
    PCIXenPlatformState *d = (PCIXenPlatformState *)pci_dev;
    register_ioport_write(addr, size, 1, xen_platform_ioport_writeb, d);
    register_ioport_read(addr, size, 1, xen_platform_ioport_readb, d);
}

static uint32_t platform_mmio_read(void *opaque, target_phys_addr_t addr)
{
    static int warnings = 0;
    if (warnings < 5) {
        fprintf(logfile, "Warning: attempted read from physical address "
                "0x%"PRIx64" in xen platform mmio space\n", (uint64_t)addr);
        warnings++;
    }
    return 0;
}

static void platform_mmio_write(void *opaque, target_phys_addr_t addr,
                                uint32_t val)
{
    static int warnings = 0;
    if (warnings < 5) {
        fprintf(logfile, "Warning: attempted write of 0x%x to physical "
                "address 0x%"PRIx64" in xen platform mmio space\n",
                val, (uint64_t)addr);
        warnings++;
    }
    return;
}

static CPUReadMemoryFunc *platform_mmio_read_funcs[3] = {
    platform_mmio_read,
    platform_mmio_read,
    platform_mmio_read,
};

static CPUWriteMemoryFunc *platform_mmio_write_funcs[3] = {
    platform_mmio_write,
    platform_mmio_write,
    platform_mmio_write,
};

static void platform_mmio_map(PCIDevice *d, int region_num,
                              uint32_t addr, uint32_t size, int type)
{
    int mmio_io_addr;

    mmio_io_addr = cpu_register_io_memory(0, platform_mmio_read_funcs,
                                          platform_mmio_write_funcs, NULL);

    cpu_register_physical_memory(addr, 0x1000000, mmio_io_addr);
}

struct pci_config_header {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t command;
    uint16_t status;
    uint8_t  revision;
    uint8_t  api;
    uint8_t  subclass;
    uint8_t  class;
    uint8_t  cache_line_size; /* Units of 32 bit words */
    uint8_t  latency_timer; /* In units of bus cycles */
    uint8_t  header_type; /* Should be 0 */
    uint8_t  bist; /* Built in self test */
    uint32_t base_address_regs[6];
    uint32_t reserved1;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_id;
    uint32_t rom_addr;
    uint32_t reserved3;
    uint32_t reserved4;
    uint8_t  interrupt_line;
    uint8_t  interrupt_pin;
    uint8_t  min_gnt;
    uint8_t  max_lat;
};

void xen_pci_save(QEMUFile *f, void *opaque)
{
    PCIXenPlatformState *d = opaque;

    pci_device_save(&d->pci_dev, f);
    qemu_put_8s(f, &d->platform_flags);
}

int xen_pci_load(QEMUFile *f, void *opaque, int version_id)
{
    PCIXenPlatformState *d = opaque;
    int ret;

    if (version_id > 2)
        return -EINVAL;

    ret = pci_device_load(&d->pci_dev, f);
    if (ret < 0)
        return ret;

    if (version_id >= 2) {
        uint8_t flags;
        qemu_get_8s(f, &flags);
        xen_platform_ioport_writeb(d, 0, flags);
    }

    return 0;
}

void pci_xen_platform_init(PCIBus *bus)
{
    PCIXenPlatformState *d;
    struct pci_config_header *pch;

    printf("Register xen platform.\n");
    d = (PCIXenPlatformState *)pci_register_device(
        bus, "xen-platform", sizeof(PCIXenPlatformState), -1, NULL, NULL);
    pch = (struct pci_config_header *)d->pci_dev.config;
    pch->vendor_id = 0x5853;
    pch->device_id = 0x0001;
    pch->command = 3; /* IO and memory access */
    pch->revision = 1;
    pch->api = 0;
    pch->subclass = 0x80; /* Other */
    pch->class = 0xff; /* Unclassified device class */
    pch->header_type = 0;
    pch->interrupt_pin = 1;

    /* Microsoft WHQL requires non-zero subsystem IDs. */
    /* http://www.pcisig.com/reflector/msg02205.html.  */
    pch->subsystem_vendor_id = pch->vendor_id; /* Duplicate vendor id.  */
    pch->subsystem_id        = 0x0001;         /* Hardcode sub-id as 1. */

    pci_register_io_region(&d->pci_dev, 0, 0x100,
                           PCI_ADDRESS_SPACE_IO, platform_ioport_map);

    /* reserve 16MB mmio address for share memory*/
    pci_register_io_region(&d->pci_dev, 1, 0x1000000,
                           PCI_ADDRESS_SPACE_MEM_PREFETCH, platform_mmio_map);

    xen_platform_ioport_writeb(d, 0, 0);

    register_savevm("platform", 0, 2, xen_pci_save, xen_pci_load, d);
    printf("Done register platform.\n");
}
