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

static int
xendbg_serhnd = -1;

static void
xendbg_put_char(u8 data)
{
	serial_putc(xendbg_serhnd, data);
}

static u8
xendbg_get_char(void)
{
	u8 ch;
	extern unsigned char __serial_getc(int handle);
	ch = __serial_getc(xendbg_serhnd);
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
attempt_receive_packet(char *recv_buf)
{
	int count;
	u8 csum;
	u8 received_csum;
	u8 ch;

	/* Skip over everything up to the first '$' */
	while ((ch = xendbg_get_char()) != '$')
		;
	csum = 0;
	for (count = 0; count < 4096; count++) {
		ch = xendbg_get_char();
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
	received_csum = hex_char_val(xendbg_get_char()) * 16 +
		hex_char_val(xendbg_get_char());
	if (received_csum == csum) {
		return 0;
	} else {
		return -1;
	}
}

/* Send a string of bytes to the debugger. */
static void
xendbg_send(const char *buf, int count)
{
	int x;
	for (x = 0; x < count; x++)
		xendbg_put_char(buf[x]);
}

/* Receive a command, discarding up to ten packets with csum
 * errors.  Acknowledges all received packets. */
static int
receive_command(char *recv_buf)
{
	int r;
	int count;

	count = 0;
	do {
		r = attempt_receive_packet(recv_buf);
		if (r < 0)
			xendbg_send("-", 1);
		else
			xendbg_send("+", 1);
		count++;
	} while (r < 0 && count < 10);
	return r;
}

static void
u32_to_hex_u8(unsigned char val, char *buf)
{
	sprintf(buf, "%.02x\n", val);
}

static void
u32_to_hex_u32(unsigned val, char *buf)
{
	sprintf(buf, "%.08x\n", val);
}

static void
xendbg_send_hex_u8(unsigned char val)
{
	char buf[3];
	u32_to_hex_u8(val, buf);
	xendbg_send(buf, 2);
}

static u8
xendbg_reply_csum;

static void
xendbg_start_reply(void)
{
	xendbg_reply_csum = 0;
	xendbg_send("$", 1);
}

static void
xendbg_sendrep_data(const unsigned char *data, unsigned long len)
{
	int x;

	for (x = 0; x < len; x++) {
		xendbg_put_char(data[x]);
		xendbg_reply_csum += data[x];
	}
}

/* Return 0 if the reply was successfully received, !0 otherwise. */
static int
xendbg_finish_reply(void)
{
	char ch;

	xendbg_send("#", 1);
	xendbg_send_hex_u8(xendbg_reply_csum);
	ch = xendbg_get_char();
	if (ch == '+')
		return 0;
	else
		return 1;
}

static void
xendbg_sendrep_hex_u8(unsigned val)
{
	char buf[3];
	u32_to_hex_u8(val, buf);
	xendbg_sendrep_data(buf, 2);
}

static void
xendbg_sendrep_hex_u32(unsigned val)
{
	char buf[9];
	u32_to_hex_u32(val, buf);
	xendbg_sendrep_data(buf, 8);
}

static void
xendbg_sendrep_hex_u32_le(unsigned val)
{
	val = (((val >> 0) & 0xff) << 24) |
		(((val >> 8) & 0xff) << 16) |
		(((val >> 16) & 0xff) << 8) |
		(((val >> 24) & 0xff) << 0);
	xendbg_sendrep_hex_u32(val);
}

static int
handle_memory_read_command(unsigned long addr, unsigned long length)
{
	int x;
	unsigned char val;
	int r;
	unsigned old_s_limit;

	dbg_printk("Memory read starting at %lx, length %lx.\n", addr,
		   length);
	old_s_limit = current->addr_limit.seg;
	current->addr_limit.seg = ~0;
	xendbg_start_reply();
	for (x = 0; x < length; x++) {
		r = copy_from_user(&val, (void *)(addr + x), 1);
		if (r != 0) {
			dbg_printk("Error reading from %lx.\n", addr + x);
			break;
		}
		xendbg_sendrep_hex_u8(val);
	}
	if (x == 0)
		xendbg_sendrep_data("E05", 3);
	dbg_printk("Read done.\n");
	current->addr_limit.seg = old_s_limit;
	return xendbg_finish_reply();
}

static int
xendbg_send_reply(const char *buf)
{
	xendbg_start_reply();
	xendbg_sendrep_data(buf, strlen(buf));
	return xendbg_finish_reply();
}

static int
handle_register_read_command(struct pt_regs *regs)
{
	xendbg_start_reply();
	xendbg_sendrep_hex_u32_le(regs->eax);
	xendbg_sendrep_hex_u32_le(regs->ecx);
	xendbg_sendrep_hex_u32_le(regs->edx);
	xendbg_sendrep_hex_u32_le(regs->ebx);
	xendbg_sendrep_hex_u32_le(regs->esp);
	xendbg_sendrep_hex_u32_le(regs->ebp);
	xendbg_sendrep_hex_u32_le(regs->esi);
	xendbg_sendrep_hex_u32_le(regs->edi);
	xendbg_sendrep_hex_u32_le(regs->eip);
	xendbg_sendrep_hex_u32_le(regs->eflags);
	xendbg_sendrep_hex_u32_le(regs->xcs);
	xendbg_sendrep_hex_u32_le(regs->xss);
	xendbg_sendrep_hex_u32_le(regs->xes);
	xendbg_sendrep_hex_u32_le(regs->xfs);
	xendbg_sendrep_hex_u32_le(regs->xgs);
	return xendbg_finish_reply();
}

static unsigned long
hex_to_int(const char *start, const char **end)
{
	return simple_strtol(start, (char **)end, 16);
}

static int
process_command(const char *received_packet, struct pt_regs *regs)
{
	const char *ptr;
	unsigned long addr, length;
	int retry;
	int counter;
	int resume = 0;

	/* Repeat until gdb acks the reply */
	counter = 0;
	do {
		switch (received_packet[0]) {
		case 'g': /* Read registers */
			retry = handle_register_read_command(regs);
			break;
		case 'm': /* Read memory */
			addr = hex_to_int(received_packet + 1, &ptr);
			if (ptr == received_packet + 1 ||
			    ptr[0] != ',') {
				xendbg_send_reply("E03");
				return 0;
			}
			length = hex_to_int(ptr + 1, &ptr);
			if (ptr[0] != 0) {
				xendbg_send_reply("E04");
				return 0;
			}
			retry =
				handle_memory_read_command(addr,
							   length);
			break;
		case 'G': /* Write registers */
		case 'M': /* Write memory */
			retry = xendbg_send_reply("E02");
			break;
		case 'D':
			resume = 1;
			retry = xendbg_send_reply("");
			break;
		case 'c': /* Resume at current address */
		case 's': /* Single step */
		case '?':
			retry = xendbg_send_reply("S01");
			break;
		default:
			retry = xendbg_send_reply("");
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

void
__trap_to_xendbg(struct pt_regs *regs)
{
	int resume = 0;
	int r;
	static int xendbg_running;
	static char recv_buf[4096];

	if (xendbg_serhnd < 0) {
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

	while (resume == 0) {
		r = receive_command(recv_buf);
		if (r < 0) {
			dbg_printk("GDB disappeared, trying to resume Xen...\n");
			resume = 1;
		} else
			resume = process_command(recv_buf, regs);
	}
	xendbg_running = 0;
}

void
initialize_xendbg(void)
{
	extern char opt_xendbg[];

	if (!strcmp(opt_xendbg, "none"))
		return;
	xendbg_serhnd = parse_serial_handle(opt_xendbg);
	if (xendbg_serhnd == -1)
		panic("Can't parse %s as XDB serial info.\n", opt_xendbg);

	/* Acknowledge any spurious GDB packets. */
	xendbg_put_char('+');

	printk("Xendbg initialised.\n");
}
