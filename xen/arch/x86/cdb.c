/* Simple hacked-up version of pdb for use in post-mortem debugging of
   Xen and domain 0. This should be a little cleaner, hopefully.  Note
   that we can't share a serial line with PDB. */
/* We try to avoid assuming much about what the rest of the system is
   doing.  In particular, dynamic memory allocation is out of the
   question. */
/* Resuming after we've stopped used to work, but more through luck
   than any actual intention.  It doesn't at the moment. */
#include <xen/lib.h>
#include <asm/uaccess.h>
#include <xen/serial.h>
#include <asm/irq.h>
#include <xen/spinlock.h>
#include <asm/debugger.h>
#include <asm/init.h>

/* Printk isn't particularly safe just after we've trapped to the
   debugger. so avoid it. */
#define dbg_printk(...)

static unsigned char opt_cdb[30] = "none";
string_param("cdb", opt_cdb);

struct xendbg_context {
	int serhnd;
	u8 reply_csum;
	int currently_attached:1;
};

/* Like copy_from_user, but safe to call with interrupts disabled.

   Trust me, and don't look behind the curtain. */
static unsigned
dbg_copy_from_user(void *dest, const void *src, unsigned len)
{
	int __d0, __d1, __d2;
	ASSERT(!local_irq_is_enabled());
	__asm__ __volatile__(
		"1:	rep; movsb\n"
		"2:\n"
		".section __pre_ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 1b,2b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 1b,2b\n"
		".previous\n"
		: "=c"(__d2), "=D" (__d0), "=S" (__d1)
		: "0"(len), "1"(dest), "2"(src)
		: "memory");
	ASSERT(!local_irq_is_enabled());
	return __d2;
}

static void
xendbg_put_char(u8 data, struct xendbg_context *ctx)
{
	ctx->reply_csum += data;
	serial_putc(ctx->serhnd, data);
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
	while ((ch = irq_serial_getc(ctx->serhnd)) != '$')
		;
	csum = 0;
	for (count = 0; count < 4096; count++) {
		ch = irq_serial_getc(ctx->serhnd);
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
	received_csum = hex_char_val(irq_serial_getc(ctx->serhnd)) * 16 +
		hex_char_val(irq_serial_getc(ctx->serhnd));
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

	ch = irq_serial_getc(ctx->serhnd);
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
	char buf[2];

	dbg_printk("Memory read starting at %lx, length %lx.\n", addr,
		   length);
	xendbg_start_reply(ctx);
	for (x = 0; x < length; x++) {
		r = dbg_copy_from_user(&val, (void *)(addr + x), 1);
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
handle_register_read_command(struct xen_regs *regs, struct xendbg_context *ctx)
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
		bswab32(regs->cs),
		bswab32(regs->ss),
		bswab32(regs->es),
		bswab32(regs->fs),
		bswab32(regs->gs));
	return xendbg_send_reply(buf, ctx);
}

static int
process_command(char *received_packet, struct xen_regs *regs,
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
			ASSERT(!local_irq_is_enabled());
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
			ASSERT(!local_irq_is_enabled());
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
__trap_to_cdb(struct xen_regs *regs)
{
	int resume = 0;
	int r;
	static atomic_t xendbg_running = ATOMIC_INIT(1);
	static char recv_buf[4096];
	unsigned flags;
	unsigned old_watchdog;

	if (xdb_ctx.serhnd < 0) {
		dbg_printk("Debugger not ready yet.\n");
		return;
	}

	/* We rely on our caller to ensure we're only on one processor
	 * at a time... We should probably panic here, but given that
	 * we're a debugger we should probably be a little tolerant of
	 * things going wrong. */
	/* We don't want to use a spin lock here, because we're doing
	   two distinct things:

	   1 -- we don't want to run on more than one processor at a time,
	        and
	   2 -- we want to do something sensible if we re-enter ourselves.

	   Spin locks are good for 1, but useless for 2. */
	if (!atomic_dec_and_test(&xendbg_running)) {
		printk("WARNING WARNING WARNING: Avoiding recursive xendbg.\n");
		atomic_inc(&xendbg_running);
		return;
	}

	smp_send_stop();

	/* Try to make things a little more stable by disabling
	   interrupts while we're here. */
	local_irq_save(flags);

	old_watchdog = watchdog_on;
	watchdog_on = 0;

	/* Shouldn't really do this, but otherwise we stop for no
	   obvious reason, which is Bad */
	printk("Waiting for GDB to attach to XenDBG\n");

	/* If gdb is already attached, tell it we've stopped again. */
	if (xdb_ctx.currently_attached) {
		do {
			r = xendbg_send_reply("S01", &xdb_ctx);
		} while (r != 0);
	}

	while (resume == 0) {
		ASSERT(!local_irq_is_enabled());
		r = receive_command(recv_buf, &xdb_ctx);
		ASSERT(!local_irq_is_enabled());
		if (r < 0) {
			dbg_printk("GDB disappeared, trying to resume Xen...\n");
			resume = 1;
		} else {
			ASSERT(!local_irq_is_enabled());
			resume = process_command(recv_buf, regs, &xdb_ctx);
			ASSERT(!local_irq_is_enabled());
		}
	}
	watchdog_on = old_watchdog;
	atomic_inc(&xendbg_running);
	local_irq_restore(flags);
}

static int
initialize_xendbg(void)
{
	if (!strcmp(opt_cdb, "none"))
		return 0;
	xdb_ctx.serhnd = parse_serial_handle(opt_cdb);
	if (xdb_ctx.serhnd == -1)
		panic("Can't parse %s as CDB serial info.\n", opt_cdb);

	/* Acknowledge any spurious GDB packets. */
	xendbg_put_char('+', &xdb_ctx);

	printk("Xendbg initialised.\n");
	return 0;
}

__initcall(initialize_xendbg);
