/******************************************************************************
 * ioport_emulate.c
 * 
 * Handle I/O port access quirks of various platforms.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/dmi.h>

static void ioemul_handle_proliant_quirk(
    u8 opcode, char *io_emul_stub, struct cpu_user_regs *regs)
{
    uint16_t port = regs->edx;
    uint8_t value = regs->eax;

    if ( (opcode != 0xee) || (port != 0xcd4) || !(value & 0x80) )
        return;

    /*    pushf */
    io_emul_stub[0] = 0x9c;
    /*    cli */
    io_emul_stub[1] = 0xfa;
    /*    out %al,%dx */
    io_emul_stub[2] = 0xee;
    /* 1: in %dx,%al */
    io_emul_stub[3] = 0xec;
    /*    test $0x80,%al */
    io_emul_stub[4] = 0xa8;
    io_emul_stub[5] = 0x80;
    /*    jnz 1b */
    io_emul_stub[6] = 0x75;
    io_emul_stub[7] = 0xfb;
    /*    popf */
    io_emul_stub[8] = 0x9d;
    /*    ret */
    io_emul_stub[9] = 0xc3;
}

static int __init proliant_quirk(struct dmi_system_id *d)
{
    ioemul_handle_quirk = ioemul_handle_proliant_quirk;
    return 0;
}

/* This table is the set of system-specific I/O emulation hooks. */
static struct dmi_system_id __initdata ioport_quirks_tbl[] = {
    /*
     * I/O emulation hook for certain HP ProLiant servers with
     * 'special' SMM goodness.
     */
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant DL3xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant DL3"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant DL5xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant DL5"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant DL7xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant DL7"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant ML3xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant ML3"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant ML5xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant ML5"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant BL2xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant BL2"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant BL4xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant BL4"),
        },
    },
    {
        .callback = proliant_quirk,
        .ident = "HP ProLiant BL6xx",
        .matches = {
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant BL6"),
        },
    },
    { }
};

static int __init ioport_quirks_init(void)
{
    dmi_check_system(ioport_quirks_tbl);
    return 0;
}
__initcall(ioport_quirks_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
