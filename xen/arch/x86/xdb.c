/* Simple hacked-up version of pdb for us in post-mortem debugging of
   Xen and domain 0. This should be a little cleaner, hopefully.  Note
   that we can't share a serial line with PDB. */
#include <xen/lib.h>
#include <asm/uaccess.h>
#include <xen/serial.h>
#include <asm/irq.h>
#include <xen/spinlock.h>

/* Printk isn't particularly safe just after we've trapped to the
   debugger. so avoid it. */
#define dbg_printk(...)

struct xendbg_context {
	int serhnd;
	u8 reply_csum;
	int currently_attached:1;
};

static void
xendbg_put_char(u8 data, struct xendbg_context *ctx)
{
	ctx->reply_csum += data;
	serial_putc(ctx->serhnd, data);
}

static u8
xendbg_get_char(struct xendbg_context *ctx)
{
	u8 ch;
	extern unsigned char __serial_getc(int handle);
	ch = __serial_getc(ctx->serhnd);
	return ch;
}

static int
hex_char_val(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		BUG();
	return -1;
}

/* Receive a command.  Returns -1 on csum error, 0 otherwise. */
/* Does not acknowledge. */
static int
attempt_receive_packet(char *recv_buf, struct xendbg_context *ctx)
{
	int count;
	u8 csum;
	u8 received_csum;
	u8 ch;

	/* Skip over everything up to the first '$' */
	while ((ch = xendbg_get_char(ctx)) != '$')
		;
	csum = 0;
	for (count = 0; count < 4096; count++) {
		ch = xendbg_get_char(ctx);
		if (ch == '#')
			break;
		recv_buf[count] = ch;
		csum += ch;
	}
	if (count == 4096) {
		dbg_printk("WARNING: GDB sent a stupidly big packet.\n");
		return -1;
	}
	recv_buf[count] = 0;
	received_csum = hex_char_val(xendbg_get_char(ctx)) * 16 +
		hex_char_val(xendbg_get_char(ctx));
	if (received_csum == csum) {
		return 0;
	} else {
		return -1;
	}
}

/* Send a string of bytes to the debugger. */
static void
xendbg_send(const char *buf, int count, struct xendbg_context *ctx)
{
	int x;
	for (x = 0; x < count; x++)
		xendbg_put_char(buf[x], ctx);
}

/* Receive a command, discarding up to ten packets with csum
 * errors.  Acknowledges all received packets. */
static int
receive_command(char *recv_buf, struct xendbg_context *ctx)
{
	int r;
	int count;

	count = 0;
	do {
		r = attempt_receive_packet(recv_buf, ctx);
		if (r < 0)
			xendbg_put_char('-', ctx);
		else
			xendbg_put_char('+', ctx);
		count++;
	} while (r < 0 && count < 10);
	return r;
}

static void
xendbg_start_reply(struct xendbg_context *ctx)
{
	xendbg_put_char('$', ctx);
	ctx->reply_csum = 0;
}

/* Return 0 if the reply was successfully received, !0 otherwise. */
static int
xendbg_finish_reply(struct xendbg_context *ctx)
{
	char ch;
	char buf[3];

	sprintf(buf, "%.02x\n", ctx->reply_csum);

	xendbg_put_char('#', ctx);
	xendbg_send(buf, 2, ctx);

	ch = xendbg_get_char(ctx);
	if (ch == '+')
		return 0;
	else
		return 1;
}

/* Swap the order of the bytes in a work. */
static inline unsigned
bswab32(unsigned val)
{
	return (((val >> 0) & 0xff) << 24) |
		(((val >> 8) & 0xff) << 16) |
		(((val >> 16) & 0xff) << 8) |
		(((val >> 24) & 0xff) << 0);
}

static int
handle_memory_read_command(unsigned long addr, unsigned long length,
			   struct xendbg_context *ctx)
{
	int x;
	unsigned char val;
	int r;
	unsigned old_s_limit;
	char buf[2];

	dbg_printk("Memory read starting at %lx, length %lx.\n", addr,
		   length);
	old_s_limit = current->addr_limit.seg;
	current->addr_limit.seg = ~0;
	xendbg_start_reply(ctx);
	for (x = 0; x < length; x++) {
		r = copy_from_user(&val, (void *)(addr + x), 1);
		if (r != 0) {
			dbg_printk("Error reading from %lx.\n", addr + x);
			break;
		}
		sprintf(buf, "%.02x", val);
		xendbg_send(buf, 2, ctx);
	}
	if (x == 0)
		xendbg_send("E05", 3, ctx);
	dbg_printk("Read done.\n");
	current->addr_limit.seg = old_s_limit;
	return xendbg_finish_reply(ctx);
}

static int
xendbg_send_reply(const char *buf, struct xendbg_context *ctx)
{
	xendbg_start_reply(ctx);
	xendbg_send(buf, strlen(buf), ctx);
	return xendbg_finish_reply(ctx);
}

static int
handle_register_read_command(struct pt_regs *regs, struct xendbg_context *ctx)
{
	char buf[121];

	sprintf(buf,
		"%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x%.08x",
		bswab32(regs->eax),
		bswab32(regs->ecx),
		bswab32(regs->edx),
		bswab32(regs->ebx),
		bswab32(regs->esp),
		bswab32(regs->ebp),
		bswab32(regs->esi),
		bswab32(regs->edi),
		bswab32(regs->eip),
		bswab32(regs->eflags),
		bswab32(regs->xcs),
		bswab32(regs->xss),
		bswab32(regs->xes),
		bswab32(regs->xfs),
		bswab32(regs->xgs));
	return xendbg_send_reply(buf, ctx);
}

static int
process_command(char *received_packet, struct pt_regs *regs,
		struct xendbg_context *ctx)
{
	char *ptr;
	unsigned long addr, length;
	int retry;
	int counter;
	int resume = 0;

	/* Repeat until gdb acks the reply */
	counter = 0;
	do {
		switch (received_packet[0]) {
		case 'g': /* Read registers */
			retry = handle_register_read_command(regs, ctx);
			break;
		case 'm': /* Read memory */
			addr = simple_strtoul(received_packet + 1, &ptr, 16);
			if (ptr == received_packet + 1 ||
			    ptr[0] != ',') {
				xendbg_send_reply("E03", ctx);
				return 0;
			}
			length = simple_strtoul(ptr + 1, &ptr, 16);
			if (ptr[0] != 0) {
				xendbg_send_reply("E04", ctx);
				return 0;
			}
			retry =
				handle_memory_read_command(addr,
							   length,
							   ctx);
			break;
		case 'G': /* Write registers */
		case 'M': /* Write memory */
			retry = xendbg_send_reply("E02", ctx);
			break;
		case 'D':
			resume = 1;
			ctx->currently_attached = 0;
			retry = xendbg_send_reply("", ctx);
			break;
		case 'c': /* Resume at current address */
			ctx->currently_attached = 1;
			resume = 1;
			retry = 0;
			break;
		case 'Z': /* We need to claim to support these or gdb
			     won't let you continue the process. */
		case 'z':
			retry = xendbg_send_reply("OK", ctx);
			break;

		case 's': /* Single step */
		case '?':
			retry = xendbg_send_reply("S01", ctx);
			break;
		default:
			retry = xendbg_send_reply("", ctx);
			break;
		}
		counter++;
	} while (retry == 1 && counter < 10);
	if (retry) {
		dbg_printk("WARNING: gdb disappeared when we were trying to send it a reply.\n");
		return 1;
	}
	return resume;
}

static struct xendbg_context
xdb_ctx = {
	serhnd : -1
};

void
__trap_to_xendbg(struct pt_regs *regs)
{
	int resume = 0;
	int r;
	static int xendbg_running;
	static char recv_buf[4096];
	unsigned flags;

	if (xdb_ctx.serhnd < 0) {
		dbg_printk("Debugger not ready yet.\n");
		return;
	}
	/* We rely on our caller to ensure we're only on one processor
	 * at a time... We should probably panic here, but given that
	 * we're a debugger we should probably be a little tolerant of
	 * things going wrong. */
	if (xendbg_running) {
		dbg_printk("WARNING WARNING WARNING: Avoiding recursive xendbg.\n");
		return;
	}
	xendbg_running = 1;

	/* Shouldn't really do this, but otherwise we stop for no
	   obvious reason, which is Bad */
	printk("Waiting for GDB to attach to XenDBG\n");

	/* Try to make things a little more stable by disabling
	   interrupts while we're here. */
	local_irq_save(flags);

	/* If gdb is already attached, tell it we've stopped again. */
	if (xdb_ctx.currently_attached) {
		do {
			r = xendbg_send_reply("S01", &xdb_ctx);
		} while (r != 0);
	}

	while (resume == 0) {
		r = receive_command(recv_buf, &xdb_ctx);
		if (r < 0) {
			dbg_printk("GDB disappeared, trying to resume Xen...\n");
			resume = 1;
		} else
			resume = process_command(recv_buf, regs, &xdb_ctx);
	}
	xendbg_running = 0;
	local_irq_restore(flags);
}

void
initialize_xendbg(void)
{
	extern char opt_xendbg[];

	if (!strcmp(opt_xendbg, "none"))
		return;
	xdb_ctx.serhnd = parse_serial_handle(opt_xendbg);
	if (xdb_ctx.serhnd == -1)
		panic("Can't parse %s as XDB serial info.\n", opt_xendbg);

	/* Acknowledge any spurious GDB packets. */
	xendbg_put_char('+', &xdb_ctx);

	printk("Xendbg initialised.\n");
}
