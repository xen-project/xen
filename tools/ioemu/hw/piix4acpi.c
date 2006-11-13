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
#define FREQUENCE_PMTIMER  3579545
/* acpi register bit define here  */

/* PM1_STS */
#define TMROF_STS         (1 << 0)
#define BM_STS            (1 << 4)
#define GBL_STS           (1 << 5)
#define PWRBTN_STS        (1 << 8)
#define RTC_STS           (1 << 10)
#define PRBTNOR_STS       (1 << 11)
#define WAK_STS           (1 << 15)
/* PM1_EN */
#define TMROF_EN          (1 << 0)
#define GBL_EN            (1 << 5)
#define PWRBTN_EN         (1 << 8)
#define RTC_EN            (1 << 10)
/* PM1_CNT */
#define SCI_EN            (1 << 0)
#define GBL_RLS           (1 << 2)
#define SLP_EN            (1 << 13)

/* Bits of PM1a register define here  */
#define SLP_TYP_MASK    0x1C00
#define SLP_VAL         0x1C00

typedef struct AcpiDeviceState AcpiDeviceState;
AcpiDeviceState *acpi_device_table;

typedef struct PM1Event_BLK {
    uint16_t pm1_status; /* pm1a_EVT_BLK */
    uint16_t pm1_enable; /* pm1a_EVT_BLK+2 */
}PM1Event_BLK;

typedef struct PCIAcpiState {
    PCIDevice dev;
    uint16_t irq;
    uint16_t pm1_status; /* pm1a_EVT_BLK */
    uint16_t pm1_enable; /* pm1a_EVT_BLK+2 */
    uint16_t pm1_control; /* pm1a_ECNT_BLK */
    uint32_t pm1_timer; /* pmtmr_BLK */
    uint64_t old_vmck_ticks; /* using vm_clock counter */
} PCIAcpiState;

static PCIAcpiState *acpi_state;

static void acpi_reset(PCIAcpiState *s)
{
    uint8_t *pci_conf;
    pci_conf = s->dev.config;

    pci_conf[0x42] = 0x00;
    pci_conf[0x43] = 0x00;
    s->irq = 9;
    s->pm1_status = 0;
    s->pm1_enable = 0x00;    /* TMROF_EN should cleared */
    s->pm1_control = SCI_EN; /* SCI_EN */
    s->pm1_timer = 0;
    s->old_vmck_ticks = qemu_get_clock(vm_clock);
}

/*byte access  */
static void acpiPm1Status_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    if ((val&TMROF_STS)==TMROF_STS)
        s->pm1_status = s->pm1_status&!TMROF_STS;

    if ((val&GBL_STS)==GBL_STS)
        s->pm1_status = s->pm1_status&!GBL_STS;

/*     printf("acpiPm1Status_writeb \n addr %x val:%x pm1_status:%x \n", addr, val,s->pm1_status); */
}

static uint32_t acpiPm1Status_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = s->pm1_status;
/*         printf("acpiPm1Status_readb \n addr %x val:%x\n", addr, val); */

   return val;
}

static void acpiPm1StatusP1_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_status = (val<<8)||(s->pm1_status);
/*     printf("acpiPm1StatusP1_writeb \n addr %x val:%x\n", addr, val); */
}

static uint32_t acpiPm1StatusP1_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = (s->pm1_status)>>8;
    printf("acpiPm1StatusP1_readb \n addr %x val:%x\n", addr, val);

    return val;
}

static void acpiPm1Enable_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_enable = val;
/*   printf("acpiPm1Enable_writeb \n addr %x val:%x\n", addr, val); */
}

static uint32_t acpiPm1Enable_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = (s->pm1_enable)||0x1;
/*  printf("acpiPm1Enable_readb \n addr %x val:%x\n", addr, val); */

    return val;
}

static void acpiPm1EnableP1_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_enable = (val<<8)||(s->pm1_enable);
/*    printf("acpiPm1EnableP1_writeb \n addr %x val:%x\n", addr, val); */

}

static uint32_t acpiPm1EnableP1_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = (s->pm1_enable)>>8;
/*  printf("acpiPm1EnableP1_readb \n addr %x val:%x\n", addr, val); */

    return val;
}

static void acpiPm1Control_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_control = val;
/*  printf("acpiPm1Control_writeb \n addr %x val:%x\n", addr, val); */

}

static uint32_t acpiPm1Control_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = s->pm1_control;
/*    printf("acpiPm1Control_readb \n addr %x val:%x\n", addr, val); */

    return val;
}

static void acpiPm1ControlP1_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_control = (val<<8)||(s->pm1_control);
/*    printf("acpiPm1ControlP1_writeb \n addr %x val:%x\n", addr, val); */

    // Check for power off request

    if (((val & SLP_EN) != 0) &&
        ((val & SLP_TYP_MASK) == SLP_VAL)) {
        s->pm1_timer=0x0; //clear ACPI timer
        qemu_system_shutdown_request();
    }
}

static uint32_t acpiPm1ControlP1_readb(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = (s->pm1_control)>>8;
/*    printf("acpiPm1ControlP1_readb \n addr %x val:%x\n", addr, val); */

    return val;
}


/* word access   */

static void acpiPm1Status_writew(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    if ((val&TMROF_STS)==TMROF_STS)
        s->pm1_status = s->pm1_status&!TMROF_STS;

    if ((val&GBL_STS)==GBL_STS)
        s->pm1_status = s->pm1_status&!GBL_STS;

/*    printf("acpiPm1Status_writew \n addr %x val:%x pm1_status:%x \n", addr, val,s->pm1_status); */
}

static uint32_t acpiPm1Status_readw(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = s->pm1_status;
/*    printf("acpiPm1Status_readw \n addr %x val:%x\n", addr, val); */

    return val;
}

static void acpiPm1Enable_writew(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_enable = val;
/*    printf("acpiPm1Enable_writew \n addr %x val:%x\n", addr, val); */

}

static uint32_t acpiPm1Enable_readw(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = s->pm1_enable;
/*    printf("acpiPm1Enable_readw \n addr %x val:%x\n", addr, val); */

   return val;
}

static void acpiPm1Control_writew(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_control = val;
/*    printf("acpiPm1Control_writew \n addr %x val:%x\n", addr, val); */

    // Check for power off request

    if (((val & SLP_EN) != 0) &&
        ((val & SLP_TYP_MASK) == SLP_VAL)) {
        qemu_system_shutdown_request();
    }

}

static uint32_t acpiPm1Control_readw(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = s->pm1_control;
/*    printf("acpiPm1Control_readw \n addr %x val:%x\n", addr, val);  */

    return val;
}

/* dword access */

static void acpiPm1Event_writel(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_status = val;
    s->pm1_enable = val>>16;
/*     printf("acpiPm1Event_writel \n addr %x val:%x \n", addr, val); */

}

static uint32_t acpiPm1Event_readl(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    uint32_t val;

    val = s->pm1_status|(s->pm1_enable<<16);
/*    printf("acpiPm1Event_readl \n addr %x val:%x\n", addr, val);    */

    return val;
}

static void acpiPm1Timer_writel(void *opaque, uint32_t addr, uint32_t val)
{
    PCIAcpiState *s = opaque;

    s->pm1_timer = val;
    s->old_vmck_ticks = qemu_get_clock(vm_clock) +
        muldiv64(val, FREQUENCE_PMTIMER, ticks_per_sec);
}

static uint32_t acpiPm1Timer_readl(void *opaque, uint32_t addr)
{
    PCIAcpiState *s = opaque;
    int64_t current_vmck_ticks = qemu_get_clock(vm_clock);
    int64_t vmck_ticks_delta = current_vmck_ticks - s->old_vmck_ticks;

    if (s->old_vmck_ticks)
        s->pm1_timer += muldiv64(vmck_ticks_delta, FREQUENCE_PMTIMER,
                                 ticks_per_sec);
    s->old_vmck_ticks = current_vmck_ticks;
    return s->pm1_timer;
}

static void acpi_map(PCIDevice *pci_dev, int region_num,
                    uint32_t addr, uint32_t size, int type)
{
    PCIAcpiState *d = (PCIAcpiState *)pci_dev;

    printf("register acpi io\n");

    /* Byte access */
    register_ioport_write(addr, 1, 1, acpiPm1Status_writeb, d);
    register_ioport_read(addr, 1, 1, acpiPm1Status_readb, d);
    register_ioport_write(addr+1, 1, 1, acpiPm1StatusP1_writeb, d);
    register_ioport_read(addr+1, 1, 1, acpiPm1StatusP1_readb, d);

    register_ioport_write(addr + 2, 1, 1, acpiPm1Enable_writeb, d);
    register_ioport_read(addr + 2, 1, 1, acpiPm1Enable_readb, d);
    register_ioport_write(addr + 2 +1, 1, 1, acpiPm1EnableP1_writeb, d);
    register_ioport_read(addr + 2 +1, 1, 1, acpiPm1EnableP1_readb, d);

    register_ioport_write(addr + 4, 1, 1, acpiPm1Control_writeb, d);
    register_ioport_read(addr + 4, 1, 1, acpiPm1Control_readb, d);
    register_ioport_write(addr + 4 + 1, 1, 1, acpiPm1ControlP1_writeb, d);
    register_ioport_read(addr + 4 +1, 1, 1, acpiPm1ControlP1_readb, d);

    /* Word access */
    register_ioport_write(addr, 2, 2, acpiPm1Status_writew, d);
    register_ioport_read(addr, 2, 2, acpiPm1Status_readw, d);

    register_ioport_write(addr + 2, 2, 2, acpiPm1Enable_writew, d);
    register_ioport_read(addr + 2, 2, 2, acpiPm1Enable_readw, d);

    register_ioport_write(addr + 4, 2, 2, acpiPm1Control_writew, d);
    register_ioport_read(addr + 4, 2, 2, acpiPm1Control_readw, d);

    /* DWord access */
    register_ioport_write(addr, 4, 4, acpiPm1Event_writel, d);
    register_ioport_read(addr, 4, 4, acpiPm1Event_readl, d);

    register_ioport_write(addr + 8, 4, 4, acpiPm1Timer_writel, d);
    register_ioport_read(addr + 8, 4, 4, acpiPm1Timer_readl, d);
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

    acpi_state = d;
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
    pci_conf[0x40] = 0x41;
    pci_conf[0x41] = 0x1f;
    acpi_map(d, 0, 0x1f40, 0x10, PCI_ADDRESS_SPACE_IO);
    acpi_reset(d);
}
