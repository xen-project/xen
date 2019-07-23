/******************************************************************************
 * ns16550.c
 * 
 * Driver for 16550-series UARTs. This driver is to be kept within Xen as
 * it permits debugging of seriously-toasted machines (e.g., in situations
 * where a device driver within a guest OS would be inaccessible).
 * 
 * Copyright (c) 2003-2005, K A Fraser
 */

#include <xen/console.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/timer.h>
#include <xen/serial.h>
#include <xen/iocap.h>
#ifdef CONFIG_HAS_PCI
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/pci_ids.h>
#endif
#include <xen/8250-uart.h>
#include <xen/vmap.h>
#include <asm/io.h>
#ifdef CONFIG_HAS_DEVICE_TREE
#include <asm/device.h>
#endif
#ifdef CONFIG_X86
#include <asm/fixmap.h>
#endif

/*
 * Configure serial port with a string:
 *   <baud>[/<base_baud>][,DPS[,<io-base>[,<irq>[,<port-bdf>[,<bridge-bdf>]]]]].
 * The tail of the string can be omitted if platform defaults are sufficient.
 * If the baud rate is pre-configured, perhaps by a bootloader, then 'auto'
 * can be specified in place of a numeric baud rate. Polled mode is specified
 * by requesting irq 0.
 */
static char __initdata opt_com1[128] = "";
static char __initdata opt_com2[128] = "";
string_param("com1", opt_com1);
string_param("com2", opt_com2);

enum serial_param_type {
    baud,
    clock_hz,
    data_bits,
    io_base,
    irq,
    parity,
    reg_shift,
    reg_width,
    stop_bits,
#ifdef CONFIG_HAS_PCI
    bridge_bdf,
    device,
    port_bdf,
#endif
    /* List all parameters before this line. */
    num_serial_params
};

static struct ns16550 {
    int baud, clock_hz, data_bits, parity, stop_bits, fifo_size, irq;
    u64 io_base;   /* I/O port or memory-mapped I/O address. */
    u64 io_size;
    int reg_shift; /* Bits to shift register offset by */
    int reg_width; /* Size of access to use, the registers
                    * themselves are still bytes */
    char __iomem *remapped_io_base;  /* Remapped virtual address of MMIO. */
    /* UART with IRQ line: interrupt-driven I/O. */
    struct irqaction irqaction;
    u8 lsr_mask;
#ifdef CONFIG_ARM
    struct vuart_info vuart;
#endif
    /* UART with no IRQ line: periodically-polled I/O. */
    struct timer timer;
    struct timer resume_timer;
    unsigned int timeout_ms;
    bool_t intr_works;
    bool_t dw_usr_bsy;
#ifdef CONFIG_HAS_PCI
    /* PCI card parameters. */
    bool_t pb_bdf_enable;   /* if =1, pb-bdf effective, port behind bridge */
    bool_t ps_bdf_enable;   /* if =1, ps_bdf effective, port on pci card */
    unsigned int pb_bdf[3]; /* pci bridge BDF */
    unsigned int ps_bdf[3]; /* pci serial port BDF */
    u32 bar;
    u32 bar64;
    u16 cr;
    u8 bar_idx;
    bool msi;
    const struct ns16550_config_param *param; /* Points into .init.*! */
#endif
} ns16550_com[2] = { { 0 } };

struct serial_param_var {
    char name[12];
    enum serial_param_type type;
};

/*
 * Enum struct keeping a table of all accepted parameter names for parsing
 * com_console_options for serial port com1 and com2.
 */
static const struct serial_param_var __initconst sp_vars[] = {
    {"baud", baud},
    {"clock-hz", clock_hz},
    {"data-bits", data_bits},
    {"io-base", io_base},
    {"irq", irq},
    {"parity", parity},
    {"reg-shift", reg_shift},
    {"reg-width", reg_width},
    {"stop-bits", stop_bits},
#ifdef CONFIG_HAS_PCI
    {"bridge", bridge_bdf},
    {"dev", device},
    {"port", port_bdf},
#endif
};

#ifdef CONFIG_HAS_PCI
struct ns16550_config {
    u16 vendor_id;
    u16 dev_id;
    enum {
        param_default, /* Must not be referenced by any table entry. */
        param_trumanage,
        param_oxford,
        param_oxford_2port,
        param_pericom_1port,
        param_pericom_2port,
        param_pericom_4port,
        param_pericom_8port,
    } param;
};

/* Defining uart config options for MMIO devices */
struct ns16550_config_param {
    unsigned int reg_shift;
    unsigned int reg_width;
    unsigned int fifo_size;
    u8 lsr_mask;
    bool_t mmio;
    bool_t bar0;
    unsigned int max_ports;
    unsigned int base_baud;
    unsigned int uart_offset;
    unsigned int first_offset;
};

/*
 * Create lookup tables for specific devices. It is assumed that if
 * the device found is MMIO, then you have indexed it here. Else, the
 * driver does nothing for MMIO based devices.
 */
static const struct ns16550_config_param __initconst uart_param[] = {
    [param_default] = {
        .reg_width = 1,
        .lsr_mask = UART_LSR_THRE,
        .max_ports = 1,
    },
    [param_trumanage] = {
        .reg_shift = 2,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = (UART_LSR_THRE | UART_LSR_TEMT),
        .mmio = 1,
        .max_ports = 1,
    },
    [param_oxford] = {
        .base_baud = 4000000,
        .uart_offset = 0x200,
        .first_offset = 0x1000,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = UART_LSR_THRE,
        .mmio = 1,
        .max_ports = 1, /* It can do more, but we would need more custom code.*/
    },
    [param_oxford_2port] = {
        .base_baud = 4000000,
        .uart_offset = 0x200,
        .first_offset = 0x1000,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = UART_LSR_THRE,
        .mmio = 1,
        .max_ports = 2,
    },
    [param_pericom_1port] = {
        .base_baud = 921600,
        .uart_offset = 8,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = UART_LSR_THRE,
        .bar0 = 1,
        .max_ports = 1,
    },
    [param_pericom_2port] = {
        .base_baud = 921600,
        .uart_offset = 8,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = UART_LSR_THRE,
        .bar0 = 1,
        .max_ports = 2,
    },
    /*
     * Of the two following ones, we can't really use all of their ports,
     * unless ns16550_com[] would get grown.
     */
    [param_pericom_4port] = {
        .base_baud = 921600,
        .uart_offset = 8,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = UART_LSR_THRE,
        .bar0 = 1,
        .max_ports = 4,
    },
    [param_pericom_8port] = {
        .base_baud = 921600,
        .uart_offset = 8,
        .reg_width = 1,
        .fifo_size = 16,
        .lsr_mask = UART_LSR_THRE,
        .bar0 = 1,
        .max_ports = 8,
    }
};
static const struct ns16550_config __initconst uart_config[] =
{
    /* Broadcom TruManage device */
    {
        .vendor_id = PCI_VENDOR_ID_BROADCOM,
        .dev_id = 0x160a,
        .param = param_trumanage,
    },
    /* OXPCIe952 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc11b,
        .param = param_oxford,
    },
    /* OXPCIe952 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc11f,
        .param = param_oxford,
    },
    /* OXPCIe952 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc138,
        .param = param_oxford,
    },
    /* OXPCIe952 2 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc158,
        .param = param_oxford_2port,
    },
    /* OXPCIe952 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc13d,
        .param = param_oxford,
    },
    /* OXPCIe952 2 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc15d,
        .param = param_oxford_2port,
    },
    /* OXPCIe952 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc40b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc40f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc41b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc41f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc42b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc42f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc43b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc43f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc44b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc44f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc45b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc45f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc46b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc46f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc47b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc47f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc48b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc48f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc49b,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc49f,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc4ab,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc4af,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc4bb,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc4bf,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc4cb,
        .param = param_oxford,
    },
    /* OXPCIe200 1 Native UART  */
    {
        .vendor_id = PCI_VENDOR_ID_OXSEMI,
        .dev_id = 0xc4cf,
        .param = param_oxford,
    },
    /* Pericom PI7C9X7951 Uno UART */
    {
        .vendor_id = PCI_VENDOR_ID_PERICOM,
        .dev_id = 0x7951,
        .param = param_pericom_1port
    },
    /* Pericom PI7C9X7952 Duo UART */
    {
        .vendor_id = PCI_VENDOR_ID_PERICOM,
        .dev_id = 0x7952,
        .param = param_pericom_2port
    },
    /* Pericom PI7C9X7954 Quad UART */
    {
        .vendor_id = PCI_VENDOR_ID_PERICOM,
        .dev_id = 0x7954,
        .param = param_pericom_4port
    },
    /* Pericom PI7C9X7958 Octal UART */
    {
        .vendor_id = PCI_VENDOR_ID_PERICOM,
        .dev_id = 0x7958,
        .param = param_pericom_8port
    }
};
#endif

static void ns16550_delayed_resume(void *data);

static u8 ns_read_reg(struct ns16550 *uart, unsigned int reg)
{
    void __iomem *addr = uart->remapped_io_base + (reg << uart->reg_shift);
#ifdef CONFIG_HAS_IOPORTS
    if ( uart->remapped_io_base == NULL )
        return inb(uart->io_base + reg);
#endif
    switch ( uart->reg_width )
    {
    case 1:
        return readb(addr);
    case 4:
        return readl(addr);
    default:
        return 0xff;
    }
}

static void ns_write_reg(struct ns16550 *uart, unsigned int reg, u8 c)
{
    void __iomem *addr = uart->remapped_io_base + (reg << uart->reg_shift);
#ifdef CONFIG_HAS_IOPORTS
    if ( uart->remapped_io_base == NULL )
        return outb(c, uart->io_base + reg);
#endif
    switch ( uart->reg_width )
    {
    case 1:
        writeb(c, addr);
        break;
    case 4:
        writel(c, addr);
        break;
    default:
        /* Ignored */
        break;
    }
}

static int ns16550_ioport_invalid(struct ns16550 *uart)
{
    return ns_read_reg(uart, UART_IER) == 0xff;
}

static void handle_dw_usr_busy_quirk(struct ns16550 *uart)
{
    if ( uart->dw_usr_bsy &&
         (ns_read_reg(uart, UART_IIR) & UART_IIR_BSY) == UART_IIR_BSY )
    {
        /* DesignWare 8250 detects if LCR is written while the UART is
         * busy and raises a "busy detect" interrupt. Read the UART
         * Status Register to clear this state.
         *
         * Allwinner/sunxi UART hardware is similar to DesignWare 8250
         * and also contains a "busy detect" interrupt. So this quirk
         * fix will also be used for Allwinner UART.
         */
        ns_read_reg(uart, UART_USR);
    }
}

static void ns16550_interrupt(
    int irq, void *dev_id, struct cpu_user_regs *regs)
{
    struct serial_port *port = dev_id;
    struct ns16550 *uart = port->uart;

    uart->intr_works = 1;

    while ( !(ns_read_reg(uart, UART_IIR) & UART_IIR_NOINT) )
    {
        u8 lsr = ns_read_reg(uart, UART_LSR);

        if ( (lsr & uart->lsr_mask) == uart->lsr_mask )
            serial_tx_interrupt(port, regs);
        if ( lsr & UART_LSR_DR )
            serial_rx_interrupt(port, regs);

        /* A "busy-detect" condition is observed on Allwinner/sunxi UART
         * after LCR is written during setup. It needs to be cleared at
         * this point or UART_IIR_NOINT will never be set and this loop
         * will continue forever.
         *
         * This state can be cleared by calling the dw_usr_busy quirk
         * handler that resolves "busy-detect" for  DesignWare uart.
         */
        handle_dw_usr_busy_quirk(uart);
    }
}

/* Safe: ns16550_poll() runs as softirq so not reentrant on a given CPU. */
static DEFINE_PER_CPU(struct serial_port *, poll_port);

static void __ns16550_poll(struct cpu_user_regs *regs)
{
    struct serial_port *port = this_cpu(poll_port);
    struct ns16550 *uart = port->uart;

    if ( uart->intr_works )
        return; /* Interrupts work - no more polling */

    while ( ns_read_reg(uart, UART_LSR) & UART_LSR_DR )
    {
        if ( ns16550_ioport_invalid(uart) )
            goto out;

        serial_rx_interrupt(port, regs);
    }

    if ( ( ns_read_reg(uart, UART_LSR) & uart->lsr_mask ) == uart->lsr_mask )
        serial_tx_interrupt(port, regs);

out:
    set_timer(&uart->timer, NOW() + MILLISECS(uart->timeout_ms));
}

static void ns16550_poll(void *data)
{
    this_cpu(poll_port) = data;
#ifdef run_in_exception_handler
    run_in_exception_handler(__ns16550_poll);
#else
    __ns16550_poll(guest_cpu_user_regs());
#endif
}

static int ns16550_tx_ready(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;

    if ( ns16550_ioport_invalid(uart) )
        return -EIO;

    return ( (ns_read_reg(uart, UART_LSR) &
              uart->lsr_mask ) == uart->lsr_mask ) ? uart->fifo_size : 0;
}

static void ns16550_putc(struct serial_port *port, char c)
{
    struct ns16550 *uart = port->uart;
    ns_write_reg(uart, UART_THR, c);
}

static int ns16550_getc(struct serial_port *port, char *pc)
{
    struct ns16550 *uart = port->uart;

    if ( ns16550_ioport_invalid(uart) ||
        !(ns_read_reg(uart, UART_LSR) & UART_LSR_DR) )
        return 0;

    *pc = ns_read_reg(uart, UART_RBR);
    return 1;
}

static void pci_serial_early_init(struct ns16550 *uart)
{
#ifdef CONFIG_HAS_PCI
    if ( !uart->ps_bdf_enable || uart->io_base >= 0x10000 )
        return;

    if ( uart->pb_bdf_enable )
        pci_conf_write16(PCI_SBDF(0, uart->pb_bdf[0], uart->pb_bdf[1],
                                  uart->pb_bdf[2]),
                         PCI_IO_BASE,
                         (uart->io_base & 0xF000) |
                         ((uart->io_base & 0xF000) >> 8));

    pci_conf_write32(0, uart->ps_bdf[0], uart->ps_bdf[1], uart->ps_bdf[2],
                     PCI_BASE_ADDRESS_0,
                     uart->io_base | PCI_BASE_ADDRESS_SPACE_IO);
    pci_conf_write16(PCI_SBDF(0, uart->ps_bdf[0], uart->ps_bdf[1],
                              uart->ps_bdf[2]),
                     PCI_COMMAND, PCI_COMMAND_IO);
#endif
}

static void ns16550_setup_preirq(struct ns16550 *uart)
{
    unsigned char lcr;
    unsigned int  divisor;

    uart->intr_works = 0;

    pci_serial_early_init(uart);

    lcr = (uart->data_bits - 5) | ((uart->stop_bits - 1) << 2) | uart->parity;

    /* No interrupts. */
    ns_write_reg(uart, UART_IER, 0);

    /* Handle the DesignWare 8250 'busy-detect' quirk. */
    handle_dw_usr_busy_quirk(uart);

    /* Line control and baud-rate generator. */
    ns_write_reg(uart, UART_LCR, lcr | UART_LCR_DLAB);
    if ( uart->baud != BAUD_AUTO )
    {
        /* Baud rate specified: program it into the divisor latch. */
        divisor = uart->clock_hz / (uart->baud << 4);
        ns_write_reg(uart, UART_DLL, (char)divisor);
        ns_write_reg(uart, UART_DLM, (char)(divisor >> 8));
    }
    else
    {
        /* Baud rate already set: read it out from the divisor latch. */
        divisor  = ns_read_reg(uart, UART_DLL);
        divisor |= ns_read_reg(uart, UART_DLM) << 8;
        if ( divisor )
            uart->baud = uart->clock_hz / (divisor << 4);
        else
            printk(XENLOG_ERR
                   "Automatic baud rate determination was requested,"
                   " but a baud rate was not set up\n");
    }
    ns_write_reg(uart, UART_LCR, lcr);

    /* No flow ctrl: DTR and RTS are both wedged high to keep remote happy. */
    ns_write_reg(uart, UART_MCR, UART_MCR_DTR | UART_MCR_RTS);

    /* Enable and clear the FIFOs. Set a large trigger threshold. */
    ns_write_reg(uart, UART_FCR,
                 UART_FCR_ENABLE | UART_FCR_CLRX | UART_FCR_CLTX | UART_FCR_TRG14);
}

static void __init ns16550_init_preirq(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;

#ifdef CONFIG_HAS_IOPORTS
    /* I/O ports are distinguished by their size (16 bits). */
    if ( uart->io_base >= 0x10000 )
#endif
    {
#ifdef CONFIG_X86
        enum fixed_addresses idx = FIX_COM_BEGIN + (uart - ns16550_com);

        set_fixmap_nocache(idx, uart->io_base);
        uart->remapped_io_base = fix_to_virt(idx);
        uart->remapped_io_base += uart->io_base & ~PAGE_MASK;
#else
        uart->remapped_io_base = (char *)ioremap(uart->io_base, uart->io_size);
#endif
    }

    ns16550_setup_preirq(uart);

    /* Check this really is a 16550+. Otherwise we have no FIFOs. */
    if ( ((ns_read_reg(uart, UART_IIR) & 0xc0) == 0xc0) &&
         ((ns_read_reg(uart, UART_FCR) & UART_FCR_TRG14) == UART_FCR_TRG14) )
        uart->fifo_size = 16;
}

static void __init ns16550_init_irq(struct serial_port *port)
{
#ifdef CONFIG_HAS_PCI
    struct ns16550 *uart = port->uart;

    if ( uart->msi )
        uart->irq = create_irq(0);
#endif
}

static void ns16550_setup_postirq(struct ns16550 *uart)
{
    if ( uart->irq > 0 )
    {
        /* Master interrupt enable; also keep DTR/RTS asserted. */
        ns_write_reg(uart,
                     UART_MCR, UART_MCR_OUT2 | UART_MCR_DTR | UART_MCR_RTS);

        /* Enable receive interrupts. */
        ns_write_reg(uart, UART_IER, UART_IER_ERDAI);
    }

    if ( uart->irq >= 0 )
        set_timer(&uart->timer, NOW() + MILLISECS(uart->timeout_ms));
}

static void __init ns16550_init_postirq(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    int rc, bits;

    if ( uart->irq < 0 )
        return;

    serial_async_transmit(port);

    init_timer(&uart->timer, ns16550_poll, port, 0);
    init_timer(&uart->resume_timer, ns16550_delayed_resume, port, 0);

    /* Calculate time to fill RX FIFO and/or empty TX FIFO for polling. */
    bits = uart->data_bits + uart->stop_bits + !!uart->parity;
    uart->timeout_ms = max_t(
        unsigned int, 1, (bits * uart->fifo_size * 1000) / uart->baud);

#ifdef CONFIG_HAS_PCI
    if ( uart->bar || uart->ps_bdf_enable )
    {
        if ( !uart->param )
            pci_hide_device(0, uart->ps_bdf[0], PCI_DEVFN(uart->ps_bdf[1],
                            uart->ps_bdf[2]));
        else
        {
            if ( uart->param->mmio &&
                 rangeset_add_range(mmio_ro_ranges,
                                    uart->io_base,
                                    uart->io_base + uart->io_size - 1) )
                printk(XENLOG_INFO "Error while adding MMIO range of device to mmio_ro_ranges\n");

            if ( pci_ro_device(0, uart->ps_bdf[0],
                               PCI_DEVFN(uart->ps_bdf[1], uart->ps_bdf[2])) )
                printk(XENLOG_INFO "Could not mark config space of %02x:%02x.%u read-only.\n",
                                    uart->ps_bdf[0], uart->ps_bdf[1],
                                    uart->ps_bdf[2]);
        }

        if ( uart->msi )
        {
            struct msi_info msi = {
                .bus = uart->ps_bdf[0],
                .devfn = PCI_DEVFN(uart->ps_bdf[1], uart->ps_bdf[2]),
                .irq = rc = uart->irq,
                .entry_nr = 1
            };

            if ( rc > 0 )
            {
                struct msi_desc *msi_desc = NULL;

                pcidevs_lock();

                rc = pci_enable_msi(&msi, &msi_desc);
                if ( !rc )
                {
                    struct irq_desc *desc = irq_to_desc(msi.irq);
                    unsigned long flags;

                    spin_lock_irqsave(&desc->lock, flags);
                    rc = setup_msi_irq(desc, msi_desc);
                    spin_unlock_irqrestore(&desc->lock, flags);
                    if ( rc )
                        pci_disable_msi(msi_desc);
                }

                pcidevs_unlock();

                if ( rc )
                {
                    uart->irq = 0;
                    if ( msi_desc )
                        msi_free_irq(msi_desc);
                    else
                        destroy_irq(msi.irq);
                }
            }

            if ( rc )
                printk(XENLOG_WARNING
                       "MSI setup failed (%d) for %02x:%02x.%o\n",
                       rc, uart->ps_bdf[0], uart->ps_bdf[1], uart->ps_bdf[2]);
        }
    }
#endif

    if ( uart->irq > 0 )
    {
        uart->irqaction.handler = ns16550_interrupt;
        uart->irqaction.name    = "ns16550";
        uart->irqaction.dev_id  = port;
        if ( (rc = setup_irq(uart->irq, 0, &uart->irqaction)) != 0 )
            printk("ERROR: Failed to allocate ns16550 IRQ %d\n", uart->irq);
    }

    ns16550_setup_postirq(uart);
}

static void ns16550_suspend(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;

    stop_timer(&uart->timer);

#ifdef CONFIG_HAS_PCI
    if ( uart->bar )
       uart->cr = pci_conf_read16(PCI_SBDF(0, uart->ps_bdf[0], uart->ps_bdf[1],
                                  uart->ps_bdf[2]), PCI_COMMAND);
#endif
}

static void _ns16550_resume(struct serial_port *port)
{
#ifdef CONFIG_HAS_PCI
    struct ns16550 *uart = port->uart;

    if ( uart->bar )
    {
       pci_conf_write32(0, uart->ps_bdf[0], uart->ps_bdf[1], uart->ps_bdf[2],
                        PCI_BASE_ADDRESS_0 + uart->bar_idx*4, uart->bar);

        /* If 64 bit BAR, write higher 32 bits to BAR+4 */
        if ( uart->bar & PCI_BASE_ADDRESS_MEM_TYPE_64 )
            pci_conf_write32(0, uart->ps_bdf[0],
                        uart->ps_bdf[1], uart->ps_bdf[2],
                        PCI_BASE_ADDRESS_0 + (uart->bar_idx+1)*4, uart->bar64);

       pci_conf_write16(PCI_SBDF(0, uart->ps_bdf[0], uart->ps_bdf[1],
                                 uart->ps_bdf[2]),
                        PCI_COMMAND, uart->cr);
    }
#endif

    ns16550_setup_preirq(port->uart);
    ns16550_setup_postirq(port->uart);
}

static int delayed_resume_tries;
static void ns16550_delayed_resume(void *data)
{
    struct serial_port *port = data;
    struct ns16550 *uart = port->uart;

    if ( ns16550_ioport_invalid(port->uart) && delayed_resume_tries-- )
        set_timer(&uart->resume_timer, NOW() + RESUME_DELAY);
    else
        _ns16550_resume(port);
}

static void ns16550_resume(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;

    /*
     * Check for ioport access, before fully resuming operation.
     * On some systems, there is a SuperIO card that provides
     * this legacy ioport on the LPC bus.
     *
     * We need to wait for dom0's ACPI processing to run the proper
     * AML to re-initialize the chip, before we can use the card again.
     *
     * This may cause a small amount of garbage to be written
     * to the serial log while we wait patiently for that AML to
     * be executed. However, this is preferable to spinning in an
     * infinite loop, as seen on a Lenovo T430, when serial was enabled.
     */
    if ( ns16550_ioport_invalid(uart) )
    {
        delayed_resume_tries = RESUME_RETRIES;
        set_timer(&uart->resume_timer, NOW() + RESUME_DELAY);
    }
    else
        _ns16550_resume(port);
}

static void __init ns16550_endboot(struct serial_port *port)
{
#ifdef CONFIG_HAS_IOPORTS
    struct ns16550 *uart = port->uart;
    int rv;

    if ( uart->remapped_io_base )
        return;
    rv = ioports_deny_access(hardware_domain, uart->io_base, uart->io_base + 7);
    if ( rv != 0 )
        BUG();
#endif
}

static int __init ns16550_irq(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    return ((uart->irq > 0) ? uart->irq : -1);
}

static void ns16550_start_tx(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    u8 ier = ns_read_reg(uart, UART_IER);

    /* Unmask transmit holding register empty interrupt if currently masked. */
    if ( !(ier & UART_IER_ETHREI) )
        ns_write_reg(uart, UART_IER, ier | UART_IER_ETHREI);
}

static void ns16550_stop_tx(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;
    u8 ier = ns_read_reg(uart, UART_IER);

    /* Mask off transmit holding register empty interrupt if currently unmasked. */
    if ( ier & UART_IER_ETHREI )
        ns_write_reg(uart, UART_IER, ier & ~UART_IER_ETHREI);
}

#ifdef CONFIG_ARM
static const struct vuart_info *ns16550_vuart_info(struct serial_port *port)
{
    struct ns16550 *uart = port->uart;

    return &uart->vuart;
}
#endif

static struct uart_driver __read_mostly ns16550_driver = {
    .init_preirq  = ns16550_init_preirq,
    .init_irq     = ns16550_init_irq,
    .init_postirq = ns16550_init_postirq,
    .endboot      = ns16550_endboot,
    .suspend      = ns16550_suspend,
    .resume       = ns16550_resume,
    .tx_ready     = ns16550_tx_ready,
    .putc         = ns16550_putc,
    .getc         = ns16550_getc,
    .irq          = ns16550_irq,
    .start_tx     = ns16550_start_tx,
    .stop_tx      = ns16550_stop_tx,
#ifdef CONFIG_ARM
    .vuart_info   = ns16550_vuart_info,
#endif
};

static int __init parse_parity_char(int c)
{
    switch ( c )
    {
    case 'n':
        return UART_PARITY_NONE;
    case 'o': 
        return UART_PARITY_ODD;
    case 'e': 
        return UART_PARITY_EVEN;
    case 'm': 
        return UART_PARITY_MARK;
    case 's': 
        return UART_PARITY_SPACE;
    }
    return 0;
}

static int __init check_existence(struct ns16550 *uart)
{
    unsigned char status, scratch, scratch2, scratch3;

#ifdef CONFIG_HAS_IOPORTS
    /*
     * We can't poke MMIO UARTs until they get I/O remapped later. Assume that
     * if we're getting MMIO UARTs, the arch code knows what it's doing.
     */
    if ( uart->io_base >= 0x10000 )
        return 1;
#else
    return 1; /* Everything is MMIO */
#endif

#ifdef CONFIG_HAS_PCI
    pci_serial_early_init(uart);
#endif

    /*
     * Do a simple existence test first; if we fail this,
     * there's no point trying anything else.
     */
    scratch = ns_read_reg(uart, UART_IER);
    ns_write_reg(uart, UART_IER, 0);

    /*
     * Mask out IER[7:4] bits for test as some UARTs (e.g. TL
     * 16C754B) allow only to modify them if an EFR bit is set.
     */
    scratch2 = ns_read_reg(uart, UART_IER) & 0x0f;
    ns_write_reg(uart,UART_IER, 0x0F);
    scratch3 = ns_read_reg(uart, UART_IER) & 0x0f;
    ns_write_reg(uart, UART_IER, scratch);
    if ( (scratch2 != 0) || (scratch3 != 0x0F) )
        return 0;

    /*
     * Check to see if a UART is really there.
     * Use loopback test mode.
     */
    ns_write_reg(uart, UART_MCR, UART_MCR_LOOP | 0x0A);
    status = ns_read_reg(uart, UART_MSR) & 0xF0;
    return (status == 0x90);
}

#ifdef CONFIG_HAS_PCI
static int __init
pci_uart_config(struct ns16550 *uart, bool_t skip_amt, unsigned int idx)
{
    u64 orig_base = uart->io_base;
    unsigned int b, d, f, nextf, i;

    /* NB. Start at bus 1 to avoid AMT: a plug-in card cannot be on bus 0. */
    for ( b = skip_amt ? 1 : 0; b < 0x100; b++ )
    {
        for ( d = 0; d < 0x20; d++ )
        {
            for ( f = 0; f < 8; f = nextf )
            {
                unsigned int bar_idx = 0, port_idx = idx;
                uint32_t bar, bar_64 = 0, len, len_64;
                u64 size = 0;
                const struct ns16550_config_param *param = uart_param;

                nextf = (f || (pci_conf_read16(PCI_SBDF(0, b, d, f),
                                               PCI_HEADER_TYPE) &
                               0x80)) ? f + 1 : 8;

                switch ( pci_conf_read16(PCI_SBDF(0, b, d, f),
                                         PCI_CLASS_DEVICE) )
                {
                case 0x0700: /* single port serial */
                case 0x0702: /* multi port serial */
                case 0x0780: /* other (e.g serial+parallel) */
                    break;
                case 0xffff:
                    if ( !f )
                        nextf = 8;
                    /* fall through */
                default:
                    continue;
                }

                /* Check for params in uart_config lookup table */
                for ( i = 0; i < ARRAY_SIZE(uart_config); i++ )
                {
                    u16 vendor = pci_conf_read16(PCI_SBDF(0, b, d, f),
                                                 PCI_VENDOR_ID);
                    u16 device = pci_conf_read16(PCI_SBDF(0, b, d, f),
                                                 PCI_DEVICE_ID);

                    if ( uart_config[i].vendor_id == vendor &&
                         uart_config[i].dev_id == device )
                    {
                        param += uart_config[i].param;
                        break;
                    }
                }

                if ( port_idx >= param->max_ports )
                {
                    idx -= param->max_ports;
                    continue;
                }

                if ( !param->bar0 )
                {
                    bar_idx = idx;
                    port_idx = 0;
                }

                uart->io_base = 0;
                bar = pci_conf_read32(PCI_SBDF(0, b, d, f),
                                      PCI_BASE_ADDRESS_0 + bar_idx * 4);

                /* MMIO based */
                if ( param->mmio && !(bar & PCI_BASE_ADDRESS_SPACE_IO) )
                {
                    pci_conf_write32(0, b, d, f,
                                     PCI_BASE_ADDRESS_0 + bar_idx*4, ~0u);
                    len = pci_conf_read32(PCI_SBDF(0, b, d, f),
                                          PCI_BASE_ADDRESS_0 + bar_idx * 4);
                    pci_conf_write32(0, b, d, f,
                                     PCI_BASE_ADDRESS_0 + bar_idx*4, bar);

                    /* Handle 64 bit BAR if found */
                    if ( bar & PCI_BASE_ADDRESS_MEM_TYPE_64 )
                    {
                        bar_64 = pci_conf_read32(PCI_SBDF(0, b, d, f),
                                      PCI_BASE_ADDRESS_0 + (bar_idx + 1) * 4);
                        pci_conf_write32(0, b, d, f,
                                    PCI_BASE_ADDRESS_0 + (bar_idx+1)*4, ~0u);
                        len_64 = pci_conf_read32(PCI_SBDF(0, b, d, f),
                                    PCI_BASE_ADDRESS_0 + (bar_idx + 1) * 4);
                        pci_conf_write32(0, b, d, f,
                                    PCI_BASE_ADDRESS_0 + (bar_idx+1)*4, bar_64);
                        size  = ((u64)~0 << 32) | PCI_BASE_ADDRESS_MEM_MASK;
                        size &= ((u64)len_64 << 32) | len;
                    }
                    else
                        size = len & PCI_BASE_ADDRESS_MEM_MASK;

                    uart->io_base = ((u64)bar_64 << 32) |
                                    (bar & PCI_BASE_ADDRESS_MEM_MASK);
                }
                /* IO based */
                else if ( !param->mmio && (bar & PCI_BASE_ADDRESS_SPACE_IO) )
                {
                    pci_conf_write32(0, b, d, f,
                                     PCI_BASE_ADDRESS_0 + bar_idx*4, ~0u);
                    len = pci_conf_read32(PCI_SBDF(0, b, d, f),
                                          PCI_BASE_ADDRESS_0);
                    pci_conf_write32(0, b, d, f,
                                     PCI_BASE_ADDRESS_0 + bar_idx*4, bar);
                    size = len & PCI_BASE_ADDRESS_IO_MASK;

                    uart->io_base = bar & ~PCI_BASE_ADDRESS_SPACE_IO;
                }

                /* If we have an io_base, then we succeeded in the lookup. */
                if ( !uart->io_base )
                    continue;

                size &= -size;

                /*
                 * Require length of actually used region to be at least
                 * 8 bytes times (1 << reg_shift).
                 */
                if ( size < param->first_offset +
                            port_idx * param->uart_offset +
                            (8 << param->reg_shift) )
                    continue;

                uart->param = param;

                uart->reg_shift = param->reg_shift;
                uart->reg_width = param->reg_width;
                uart->lsr_mask = param->lsr_mask;
                uart->io_base += param->first_offset +
                                 port_idx * param->uart_offset;
                if ( param->base_baud )
                    uart->clock_hz = param->base_baud * 16;
                if ( param->fifo_size )
                    uart->fifo_size = param->fifo_size;

                uart->ps_bdf[0] = b;
                uart->ps_bdf[1] = d;
                uart->ps_bdf[2] = f;
                uart->bar_idx = bar_idx;
                uart->bar = bar;
                uart->bar64 = bar_64;
                uart->io_size = max(8U << param->reg_shift,
                                    param->uart_offset);
                uart->irq = pci_conf_read8(PCI_SBDF(0, b, d, f),
                                           PCI_INTERRUPT_PIN) ?
                            pci_conf_read8(PCI_SBDF(0, b, d, f),
                                           PCI_INTERRUPT_LINE) : 0;

                return 0;
            }
        }
    }

    if ( !skip_amt )
        return -1;

    /* No AMT found, fallback to the defaults. */
    uart->io_base = orig_base;

    return 0;
}
#endif

/*
 * Used to parse name value pairs and return which value it is along with
 * pointer for the extracted value.
 */
static enum __init serial_param_type get_token(char *token, char **value)
{
    const char *param_name;
    unsigned int i;

    param_name = strsep(&token, "=");
    if ( param_name == NULL )
        return num_serial_params;

    /* Linear search for the parameter. */
    for ( i = 0; i < ARRAY_SIZE(sp_vars); i++ )
    {
        if ( strcmp(sp_vars[i].name, param_name) == 0 )
        {
            *value = token;
            return sp_vars[i].type;
        }
    }

    return num_serial_params;
}

#define PARSE_ERR(_f, _a...)                 \
    do {                                     \
        printk( "ERROR: " _f "\n" , ## _a ); \
        return;                              \
    } while ( 0 )

#define PARSE_ERR_RET(_f, _a...)             \
    do {                                     \
        printk( "ERROR: " _f "\n" , ## _a ); \
        return false;                        \
    } while ( 0 )


static bool __init parse_positional(struct ns16550 *uart, char **str)
{
    int baud;
    const char *conf;
    char *name_val_pos;

    conf = *str;
    name_val_pos = strchr(conf, '=');

    /* Finding the end of the positional parameters. */
    while ( name_val_pos > *str )
    {
        /* Working backwards from the '=' sign. */
        name_val_pos--;
        if ( *name_val_pos == ',' )
        {
            *name_val_pos = '\0';
            name_val_pos++;
            break;
        }
    }

    *str = name_val_pos;
    /* When there are no positional parameters, we return from the function. */
    if ( conf == *str )
        return true;

    /* Parse positional parameters here. */
    if ( strncmp(conf, "auto", 4) == 0 )
    {
        uart->baud = BAUD_AUTO;
        conf += 4;
    }
    else if ( (baud = simple_strtoul(conf, &conf, 10)) != 0 )
        uart->baud = baud;

    if ( *conf == '/' )
    {
        conf++;
        uart->clock_hz = simple_strtoul(conf, &conf, 0) << 4;
    }

    if ( *conf == ',' && *++conf != ',' )
    {
        uart->data_bits = simple_strtoul(conf, &conf, 10);

        uart->parity = parse_parity_char(*conf);

        uart->stop_bits = simple_strtoul(conf + 1, &conf, 10);
    }

    if ( *conf == ',' && *++conf != ',' )
    {
#ifdef CONFIG_HAS_PCI
        if ( strncmp(conf, "pci", 3) == 0 )
        {
            if ( pci_uart_config(uart, 1/* skip AMT */, uart - ns16550_com) )
                return true;
            conf += 3;
        }
        else if ( strncmp(conf, "amt", 3) == 0 )
        {
            if ( pci_uart_config(uart, 0, uart - ns16550_com) )
                return true;
            conf += 3;
        }
        else
#endif
        {
            uart->io_base = simple_strtoul(conf, &conf, 0);
        }
    }

    if ( *conf == ',' && *++conf != ',' )
    {
#ifdef CONFIG_HAS_PCI
        if ( strncmp(conf, "msi", 3) == 0 )
        {
            conf += 3;
            uart->msi = true;
            uart->irq = 0;
        }
        else
#endif
            uart->irq = simple_strtol(conf, &conf, 10);
    }

#ifdef CONFIG_HAS_PCI
    if ( *conf == ',' && *++conf != ',' )
    {
        conf = parse_pci(conf, NULL, &uart->ps_bdf[0],
                         &uart->ps_bdf[1], &uart->ps_bdf[2]);
        if ( !conf )
            PARSE_ERR_RET("Bad port PCI coordinates");
        uart->ps_bdf_enable = true;
    }

    if ( *conf == ',' && *++conf != ',' )
    {
        if ( !parse_pci(conf, NULL, &uart->pb_bdf[0],
                        &uart->pb_bdf[1], &uart->pb_bdf[2]) )
            PARSE_ERR_RET("Bad bridge PCI coordinates");
        uart->pb_bdf_enable = true;
    }
#endif

    return true;
}

static bool __init parse_namevalue_pairs(char *str, struct ns16550 *uart)
{
    char *token, *start = str;
    char *param_value = NULL;
    bool dev_set = false;

    if ( (str == NULL) || (*str == '\0') )
        return true;

    do
    {
        /* When no tokens are found, start will be NULL */
        token = strsep(&start, ",");

        switch ( get_token(token, &param_value) )
        {
        case baud:
            uart->baud = simple_strtoul(param_value, NULL, 0);
            break;

        case clock_hz:
            uart->clock_hz = simple_strtoul(param_value, NULL, 0) << 4;
            break;

        case io_base:
            if ( dev_set )
            {
                printk(XENLOG_WARNING
                       "Can't use io_base with dev=pci or dev=amt options\n");
                break;
            }
            uart->io_base = simple_strtoul(param_value, NULL, 0);
            break;

        case irq:
            uart->irq = simple_strtoul(param_value, NULL, 0);
            break;

        case data_bits:
            uart->data_bits = simple_strtoul(param_value, NULL, 0);
            break;

        case parity:
            uart->parity = parse_parity_char(*param_value);
            break;

        case stop_bits:
            uart->stop_bits = simple_strtoul(param_value, NULL, 0);
            break;

        case reg_shift:
            uart->reg_shift = simple_strtoul(param_value, NULL, 0);
            break;

        case reg_width:
            uart->reg_width = simple_strtoul(param_value, NULL, 0);
            break;

#ifdef CONFIG_HAS_PCI
        case bridge_bdf:
            if ( !parse_pci(param_value, NULL, &uart->ps_bdf[0],
                            &uart->ps_bdf[1], &uart->ps_bdf[2]) )
                PARSE_ERR_RET("Bad port PCI coordinates\n");
            uart->ps_bdf_enable = true;
            break;

        case device:
            if ( strncmp(param_value, "pci", 3) == 0 )
            {
                pci_uart_config(uart, 1/* skip AMT */, uart - ns16550_com);
                dev_set = true;
            }
            else if ( strncmp(param_value, "amt", 3) == 0 )
            {
                pci_uart_config(uart, 0, uart - ns16550_com);
                dev_set = true;
            }
            break;

        case port_bdf:
            if ( !parse_pci(param_value, NULL, &uart->pb_bdf[0],
                            &uart->pb_bdf[1], &uart->pb_bdf[2]) )
                PARSE_ERR_RET("Bad port PCI coordinates\n");
            uart->pb_bdf_enable = true;
            break;
#endif

        default:
            PARSE_ERR_RET("Invalid parameter: %s\n", token);
        }
    } while ( start != NULL );

    return true;
}

static void __init ns16550_parse_port_config(
    struct ns16550 *uart, const char *conf)
{
    char com_console_options[128];
    char *str;

    /* No user-specified configuration? */
    if ( (conf == NULL) || (*conf == '\0') )
    {
        /* Some platforms may automatically probe the UART configuartion. */
        if ( uart->baud != 0 )
            goto config_parsed;
        return;
    }

    strlcpy(com_console_options, conf, ARRAY_SIZE(com_console_options));
    str = com_console_options;

    /* parse positional parameters and get pointer for name-value pairs */
    if ( !parse_positional(uart, &str) )
        return;

    if ( !parse_namevalue_pairs(str, uart) )
        return;

 config_parsed:
    /* Sanity checks. */
    if ( (uart->baud != BAUD_AUTO) &&
         ((uart->baud < 1200) || (uart->baud > 115200)) )
        PARSE_ERR("Baud rate %d outside supported range.", uart->baud);
    if ( (uart->data_bits < 5) || (uart->data_bits > 8) )
        PARSE_ERR("%d data bits are unsupported.", uart->data_bits);
    if ( (uart->reg_width != 1) && (uart->reg_width != 4) )
        PARSE_ERR("Accepted values of reg_width are 1 and 4 only");
    if ( (uart->stop_bits < 1) || (uart->stop_bits > 2) )
        PARSE_ERR("%d stop bits are unsupported.", uart->stop_bits);
    if ( uart->io_base == 0 )
        PARSE_ERR("I/O base address must be specified.");
    if ( !check_existence(uart) )
        PARSE_ERR("16550-compatible serial UART not present");

    /* Register with generic serial driver. */
    serial_register_uart(uart - ns16550_com, &ns16550_driver, uart);
}

static void ns16550_init_common(struct ns16550 *uart)
{
    uart->clock_hz  = UART_CLOCK_HZ;

    /* Default is no transmit FIFO. */
    uart->fifo_size = 1;

    /* Default lsr_mask = UART_LSR_THRE */
    uart->lsr_mask  = UART_LSR_THRE;
}

void __init ns16550_init(int index, struct ns16550_defaults *defaults)
{
    struct ns16550 *uart;

    if ( (index < 0) || (index > 1) )
        return;

    uart = &ns16550_com[index];

    ns16550_init_common(uart);

    uart->baud      = (defaults->baud ? :
                       console_has((index == 0) ? "com1" : "com2")
                       ? BAUD_AUTO : 0);
    uart->data_bits = defaults->data_bits;
    uart->parity    = parse_parity_char(defaults->parity);
    uart->stop_bits = defaults->stop_bits;
    uart->irq       = defaults->irq;
    uart->io_base   = defaults->io_base;
    uart->io_size   = 8;
    uart->reg_width = 1;
    uart->reg_shift = 0;

    ns16550_parse_port_config(uart, (index == 0) ? opt_com1 : opt_com2);
}

#ifdef CONFIG_HAS_DEVICE_TREE
static int __init ns16550_uart_dt_init(struct dt_device_node *dev,
                                       const void *data)
{
    struct ns16550 *uart;
    int res;
    u32 reg_shift, reg_width;
    u64 io_size;

    uart = &ns16550_com[0];

    ns16550_init_common(uart);

    uart->baud      = BAUD_AUTO;
    uart->data_bits = 8;
    uart->parity    = UART_PARITY_NONE;
    uart->stop_bits = 1;

    res = dt_device_get_address(dev, 0, &uart->io_base, &io_size);
    if ( res )
        return res;

    uart->io_size = io_size;

    ASSERT(uart->io_size == io_size); /* Detect truncation */

    res = dt_property_read_u32(dev, "reg-shift", &reg_shift);
    if ( !res )
        uart->reg_shift = 0;
    else
        uart->reg_shift = reg_shift;

    res = dt_property_read_u32(dev, "reg-io-width", &reg_width);
    if ( !res )
        uart->reg_width = 1;
    else
        uart->reg_width = reg_width;

    if ( uart->reg_width != 1 && uart->reg_width != 4 )
        return -EINVAL;

    res = platform_get_irq(dev, 0);
    if ( ! res )
        return -EINVAL;
    uart->irq = res;

    uart->dw_usr_bsy = dt_device_is_compatible(dev, "snps,dw-apb-uart");

    uart->vuart.base_addr = uart->io_base;
    uart->vuart.size = uart->io_size;
    uart->vuart.data_off = UART_THR <<uart->reg_shift;
    uart->vuart.status_off = UART_LSR<<uart->reg_shift;
    uart->vuart.status = UART_LSR_THRE|UART_LSR_TEMT;

    /* Register with generic serial driver. */
    serial_register_uart(uart - ns16550_com, &ns16550_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match ns16550_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("ns16550"),
    DT_MATCH_COMPATIBLE("ns16550a"),
    DT_MATCH_COMPATIBLE("snps,dw-apb-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(ns16550, "NS16550 UART", DEVICE_SERIAL)
        .dt_match = ns16550_dt_match,
        .init = ns16550_uart_dt_init,
DT_DEVICE_END

#endif /* HAS_DEVICE_TREE */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
