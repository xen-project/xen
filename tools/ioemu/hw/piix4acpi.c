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
#include <xen/hvm/ioreq.h>

/* PM1a_CNT bits, as defined in the ACPI specification. */
#define SCI_EN            (1 <<  0)
#define GBL_RLS           (1 <<  2)
#define SLP_TYP_Sx        (7 << 10)
#define SLP_EN            (1 << 13)

/* Sleep state type codes as defined by the \_Sx objects in the DSDT. */
/* These must be kept in sync with the DSDT (hvmloader/acpi/dsdt.asl) */
#define SLP_TYP_S4        (6 << 10)
#define SLP_TYP_S5        (7 << 10)

#define ACPI_DBG_IO_ADDR  0xb044
#define ACPI_PHP_IO_ADDR  0x10c0

#define PHP_EVT_ADD     0x0
#define PHP_EVT_REMOVE  0x3

#define ACPI_SCI_IRQ 9

/* The bit in GPE0_STS/EN to notify the pci hotplug event */
#define ACPI_PHP_GPE_BIT 3

#define ACPI_PHP_SLOT_NUM PHP_SLOT_LEN

typedef struct AcpiDeviceState AcpiDeviceState;
AcpiDeviceState *acpi_device_table;

typedef struct PCIAcpiState {
    PCIDevice dev;
    uint16_t pm1_control; /* pm1a_ECNT_BLK */
} PCIAcpiState;

typedef struct GPEState {
    /* GPE0 block */
    uint8_t gpe0_sts[ACPI_GPE0_BLK_LEN / 2];
    uint8_t gpe0_en[ACPI_GPE0_BLK_LEN / 2];

    /* SCI IRQ level */
    uint8_t sci_asserted;

} GPEState;

GPEState gpe_state;

typedef struct PHPSlots {
    struct {
        uint8_t status;    /* Apaptor stats */
    } slot[ACPI_PHP_SLOT_NUM];
    uint8_t plug_evt;      /* slot|event slot:0-no event;1-1st. event:0-remove;1-add */
} PHPSlots;

PHPSlots php_slots;

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

static void acpi_shutdown(uint32_t val)
{
    if (!(val & SLP_EN))
        return;

    switch (val & SLP_TYP_Sx) {
    case SLP_TYP_S4:
    case SLP_TYP_S5:
        qemu_system_shutdown_request();
        break;
    default:
        break;
    }
}

static void acpiPm1ControlP1_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    val <<= 8;
    s->pm1_control = ((s->pm1_control & 0xff) | val) & ~SLP_EN;

    acpi_shutdown(val);
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

    acpi_shutdown(val);
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

#ifdef CONFIG_PASSTHROUGH

static inline int test_bit(uint8_t *map, int bit)
{
    return ( map[bit / 8] & (1 << (bit % 8)) );
}

static inline void set_bit(uint8_t *map, int bit)
{
    map[bit / 8] |= (1 << (bit % 8));
}

static inline void clear_bit(uint8_t *map, int bit)
{
    map[bit / 8] &= ~(1 << (bit % 8));
}

extern FILE *logfile;
static void acpi_dbg_writel(void *opaque, uint32_t addr, uint32_t val)
{
#if defined(DEBUG)
    printf("ACPI: DBG: 0x%08x\n", val);
#endif
    fprintf(logfile, "ACPI:debug: write addr=0x%x, val=0x%x.\n", addr, val);
}

/*
 * simple PCI hotplug controller IO 
 * ACPI_PHP_IO_ADDR + :
 * 0 - the hotplug description: slot(|event(remove/add); 
 * 1 - 1st php slot ctr/sts reg
 * 2 - 2nd php slot ctr/sts reg
 * ......
 */
static uint32_t acpi_php_readb(void *opaque, uint32_t addr)
{
    PHPSlots *hotplug_slots = opaque;
    int num;
    uint32_t val; 

    switch (addr)
    {
    case ACPI_PHP_IO_ADDR:
        val = hotplug_slots->plug_evt;
        break;
    default:
        num = addr - ACPI_PHP_IO_ADDR - 1;
        val = hotplug_slots->slot[num].status;
    }

    fprintf(logfile, "ACPI PCI hotplug: read addr=0x%x, val=0x%x.\n",
            addr, val);

    return val;
}

static void acpi_php_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PHPSlots *hotplug_slots = opaque;
    int php_slot;

    fprintf(logfile, "ACPI PCI hotplug: write addr=0x%x, val=0x%x.\n",
            addr, val);

    switch (addr)
    {
    case ACPI_PHP_IO_ADDR:
        break;
    default:
        php_slot = addr - ACPI_PHP_IO_ADDR - 1;
        if ( val == 0x1 ) { /* Eject command */
            /* make _STA of the slot 0 */
            hotplug_slots->slot[php_slot].status = 0;

            /* clear the hotplug event */
            hotplug_slots->plug_evt = 0;

            /* power off the slot */
            power_off_php_slot(php_slot);

            /* signal the CP ACPI hot remove done. */
            xenstore_record_dm_state("pci-removed");
        }
    }
}

static void pcislots_save(QEMUFile* f, void* opaque)
{
    PHPSlots *s = (PHPSlots*)opaque;
    int i;
    for ( i = 0; i < ACPI_PHP_SLOT_NUM; i++ ) {
        qemu_put_8s( f, &s->slot[i].status);
    }
    qemu_put_8s(f, &s->plug_evt);
}

static int pcislots_load(QEMUFile* f, void* opaque, int version_id)
{
    PHPSlots *s = (PHPSlots*)opaque;
    int i;
    if (version_id != 1)
        return -EINVAL;
    for ( i = 0; i < ACPI_PHP_SLOT_NUM; i++ ) {
        qemu_get_8s( f, &s->slot[i].status);
    }
    qemu_get_8s(f, &s->plug_evt);
    return 0;
}

static void php_slots_init(void)
{
    PHPSlots *slots = &php_slots;
    int i;
    memset(slots, 0, sizeof(PHPSlots));

    /* update the pci slot status */
    for ( i = 0; i < PHP_SLOT_LEN; i++ ) {
        if ( test_pci_slot( PHP_TO_PCI_SLOT(i) ) == 1 )
            slots->slot[i].status = 0xf;
    }


    /* ACPI PCI hotplug controller */
    register_ioport_read(ACPI_PHP_IO_ADDR, ACPI_PHP_SLOT_NUM + 1, 1, acpi_php_readb, slots);
    register_ioport_write(ACPI_PHP_IO_ADDR, ACPI_PHP_SLOT_NUM + 1, 1, acpi_php_writeb, slots);
    register_savevm("pcislots", 0, 1, pcislots_save, pcislots_load, slots);
}

/* GPEx_STS occupy 1st half of the block, while GPEx_EN 2nd half */
static uint32_t gpe_sts_read(void *opaque, uint32_t addr)
{
    GPEState *s = opaque;

    return s->gpe0_sts[addr - ACPI_GPE0_BLK_ADDRESS];
}

/* write 1 to clear specific GPE bits */
static void gpe_sts_write(void *opaque, uint32_t addr, uint32_t val)
{
    GPEState *s = opaque;
    int hotplugged = 0;

    fprintf(logfile, "gpe_sts_write: addr=0x%x, val=0x%x.\n", addr, val);

    hotplugged = test_bit(&s->gpe0_sts[0], ACPI_PHP_GPE_BIT);
    s->gpe0_sts[addr - ACPI_GPE0_BLK_ADDRESS] &= ~val;
    if ( s->sci_asserted &&
         hotplugged &&
         !test_bit(&s->gpe0_sts[0], ACPI_PHP_GPE_BIT)) {
        fprintf(logfile, "Clear the GPE0_STS bit for ACPI hotplug & deassert the IRQ.\n");
        pic_set_irq(ACPI_SCI_IRQ, 0);
    }

}

static uint32_t gpe_en_read(void *opaque, uint32_t addr)
{
    GPEState *s = opaque;

    return s->gpe0_en[addr - (ACPI_GPE0_BLK_ADDRESS + ACPI_GPE0_BLK_LEN / 2)];
}

/* write 0 to clear en bit */
static void gpe_en_write(void *opaque, uint32_t addr, uint32_t val)
{
    GPEState *s = opaque;
    int reg_count;

    fprintf(logfile, "gpe_en_write: addr=0x%x, val=0x%x.\n", addr, val);
    reg_count = addr - (ACPI_GPE0_BLK_ADDRESS + ACPI_GPE0_BLK_LEN / 2);
    s->gpe0_en[reg_count] = val;
    /* If disable GPE bit right after generating SCI on it, 
     * need deassert the intr to avoid redundant intrs
     */
    if ( s->sci_asserted &&
         reg_count == (ACPI_PHP_GPE_BIT / 8) &&
         !(val & (1 << (ACPI_PHP_GPE_BIT % 8))) ) {
        fprintf(logfile, "deassert due to disable GPE bit.\n");
        s->sci_asserted = 0;
        pic_set_irq(ACPI_SCI_IRQ, 0);
    }

}

static void gpe_save(QEMUFile* f, void* opaque)
{
    GPEState *s = (GPEState*)opaque;
    int i;

    for ( i = 0; i < ACPI_GPE0_BLK_LEN / 2; i++ ) {
        qemu_put_8s(f, &s->gpe0_sts[i]);
        qemu_put_8s(f, &s->gpe0_en[i]);
    }

    qemu_put_8s(f, &s->sci_asserted);
    if ( s->sci_asserted ) {
        fprintf(logfile, "gpe_save with sci asserted!\n");
    }
}

static int gpe_load(QEMUFile* f, void* opaque, int version_id)
{
    GPEState *s = (GPEState*)opaque;
    int i;
    if (version_id != 1)
        return -EINVAL;

    for ( i = 0; i < ACPI_GPE0_BLK_LEN / 2; i++ ) {
        qemu_get_8s(f, &s->gpe0_sts[i]);
        qemu_get_8s(f, &s->gpe0_en[i]);
    }

    qemu_get_8s(f, &s->sci_asserted);
    return 0;
}

static void gpe_acpi_init(void)
{
    GPEState *s = &gpe_state;
    memset(s, 0, sizeof(GPEState));

    register_ioport_read(ACPI_GPE0_BLK_ADDRESS,
                         ACPI_GPE0_BLK_LEN / 2,
                         1,
                         gpe_sts_read,
                         s);
    register_ioport_read(ACPI_GPE0_BLK_ADDRESS + ACPI_GPE0_BLK_LEN / 2,
                         ACPI_GPE0_BLK_LEN / 2,
                         1,
                         gpe_en_read,
                         s);

    register_ioport_write(ACPI_GPE0_BLK_ADDRESS,
                          ACPI_GPE0_BLK_LEN / 2,
                          1,
                          gpe_sts_write,
                          s);
    register_ioport_write(ACPI_GPE0_BLK_ADDRESS + ACPI_GPE0_BLK_LEN / 2,
                          ACPI_GPE0_BLK_LEN / 2,
                          1,
                          gpe_en_write,
                          s);

    register_savevm("gpe", 0, 1, gpe_save, gpe_load, s);
}

static void acpi_sci_intr(GPEState *s)
{
    if ( !test_bit(&s->gpe0_sts[0], ACPI_PHP_GPE_BIT) &&
         test_bit(&s->gpe0_en[0], ACPI_PHP_GPE_BIT) ) {

        set_bit(&s->gpe0_sts[0], ACPI_PHP_GPE_BIT);
        s->sci_asserted = 1;
        pic_set_irq(ACPI_SCI_IRQ, 1);
        fprintf(logfile, "generate a sci for PHP.\n");
    }
}

void acpi_php_del(int pci_slot)
{
    GPEState *s = &gpe_state;
    PHPSlots *hotplug_slots = &php_slots;
    int php_slot = PCI_TO_PHP_SLOT(pci_slot);

    if ( pci_slot < PHP_SLOT_START || pci_slot >= PHP_SLOT_END ) {
        fprintf(logfile, "not find the pci slot %d when hot remove.\n", pci_slot);

        return;
    }

    /* update the php controller status */
    hotplug_slots->plug_evt = (((php_slot+1) << 4) | PHP_EVT_REMOVE);

    /* generate a SCI interrupt */
    acpi_sci_intr(s);
}

void acpi_php_add(int pci_slot)
{
    GPEState *s = &gpe_state;
    PHPSlots *hotplug_slots = &php_slots;
    int php_slot = PCI_TO_PHP_SLOT(pci_slot);
    char ret_str[30];

    if ( pci_slot < PHP_SLOT_START || pci_slot >= PHP_SLOT_END ) {
        fprintf(logfile, "hot add pci slot %d exceed.\n", pci_slot);

        if ( pci_slot == 0 )
            sprintf(ret_str, "no free hotplug slots");
        else if ( pci_slot == -1 )
            sprintf(ret_str, "wrong bdf or vslot");

        if ( strlen(ret_str) > 0 )
            xenstore_record_dm("parameter", ret_str);

        return;
    }

    /* update the php controller status */
    hotplug_slots->plug_evt = (((php_slot+1) << 4) | PHP_EVT_ADD);

    /* update the slot status as present */
    hotplug_slots->slot[php_slot].status = 0xf;

    /* power on the slot */
    power_on_php_slot(php_slot);

    /* tell Control panel which slot for the new pass-throgh dev */
    sprintf(ret_str, "0x%x", pci_slot);
    xenstore_record_dm("parameter", ret_str);

    /* signal the CP ACPI hot insert done */
    xenstore_record_dm_state("pci-inserted");

    /* generate a SCI interrupt */
    acpi_sci_intr(s);
}

#endif /* CONFIG_PASSTHROUGH */

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

#ifdef CONFIG_PASSTHROUGH
    gpe_acpi_init();
    php_slots_init();
    register_ioport_write(ACPI_DBG_IO_ADDR, 4, 4, acpi_dbg_writel, d);
#endif

    register_savevm("piix4acpi", 0, 1, piix4acpi_save, piix4acpi_load, d);
}
