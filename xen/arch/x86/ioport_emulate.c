/******************************************************************************
 * ioport_emulate.c
 *
 * Handle I/O port access quirks of various platforms.
 */

#include <xen/init.h>
#include <xen/sched.h>
#include <xen/dmi.h>

bool __ro_after_init ioemul_handle_quirk;

unsigned int ioemul_handle_proliant_quirk(
    uint8_t opcode, char *io_emul_stub, const struct cpu_user_regs *regs)
{
    static const char stub[] = {
        0x9c,       /*    pushf           */
        0xfa,       /*    cli             */
        0xee,       /*    out %al, %dx    */
        0xec,       /* 1: in %dx, %al     */
        0xa8, 0x80, /*    test $0x80, %al */
        0x75, 0xfb, /*    jnz 1b          */
        0x9d,       /*    popf            */
    };
    uint16_t port = regs->dx;
    uint8_t value = regs->al;

    if ( (opcode != 0xee) || (port != 0xcd4) || !(value & 0x80) )
        return 0;

    memcpy(io_emul_stub, stub, sizeof(stub));
    BUILD_BUG_ON(IOEMUL_QUIRK_STUB_BYTES < sizeof(stub));

    return sizeof(stub);
}

/* This table is the set of system-specific I/O emulation hooks. */
static const struct dmi_system_id __initconstrel ioport_quirks_tbl[] = {
    /*
     * I/O emulation hook for certain HP ProLiant servers with
     * 'special' SMM goodness.
     */
    {
        .ident = "HP ProLiant DL3xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant DL3")),
    },
    {
        .ident = "HP ProLiant DL5xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant DL5")),
    },
    {
        .ident = "HP ProLiant DL7xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant DL7")),
    },
    {
        .ident = "HP ProLiant ML3xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant ML3")),
    },
    {
        .ident = "HP ProLiant ML5xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant ML5")),
    },
    {
        .ident = "HP ProLiant BL2xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant BL2")),
    },
    {
        .ident = "HP ProLiant BL4xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant BL4")),
    },
    {
        .ident = "HP ProLiant BL6xx",
        DMI_MATCH2(
            DMI_MATCH(DMI_BIOS_VENDOR, "HP"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ProLiant BL6")),
    },
    { }
};

static int __init cf_check ioport_quirks_init(void)
{
    if ( dmi_check_system(ioport_quirks_tbl) )
        ioemul_handle_quirk = true;

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
