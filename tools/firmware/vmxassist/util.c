/*
 * util.c: Commonly used utility functions.
 *
 * Leendert van Doorn, leendert@watson.ibm.com
 * Copyright (c) 2005, International Business Machines Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
#include <stdarg.h>
#include <vm86.h>

#include "util.h"
#include "machine.h"

#define	isdigit(c)	((c) >= '0' && (c) <= '9')
#define	min(a, b)	((a) < (b) ? (a) : (b))

static void putchar(int);
static char *printnum(char *, unsigned long, int);
static void _doprint(void (*)(int), char const *, va_list);


void
dump_regs(struct regs *regs)
{
	printf("eax    %8x ecx    %8x edx    %8x ebx    %8x\n",
		regs->eax, regs->ecx, regs->edx, regs->ebx);
	printf("esp    %8x ebp    %8x esi    %8x edi    %8x\n",
		regs->esp, regs->ebp, regs->esi, regs->edi);
	printf("eip    %8x eflags %8x cs     %8x ds     %8x\n",
		regs->eip, regs->eflags, regs->cs, regs->ds);
	printf("es     %8x fs     %8x uss    %8x uesp   %8x\n",
		regs->es, regs->fs, regs->uss, regs->uesp);
	printf("ves    %8x vds    %8x vfs    %8x vgs    %8x\n",
		regs->ves, regs->vds, regs->vfs, regs->vgs);
	if (regs->trapno != -1 || regs->errno != -1)
		printf("trapno %8x errno  %8x\n", regs->trapno, regs->errno);

	printf("cr0    %8lx cr2    %8x cr3    %8lx cr4    %8lx\n",
		(long)oldctx.cr0, get_cr2(),
		(long)oldctx.cr3, (long)oldctx.cr4);
}

#ifdef DEBUG
void
hexdump(unsigned char *data, int sz)
{
	unsigned char *d;
	int i;

	for (d = data; sz > 0; d += 16, sz -= 16) {
		int n = sz > 16 ? 16 : sz;

		printf("%08x: ", (unsigned)d);
		for (i = 0; i < n; i++)
			printf("%02x%c", d[i], i == 7 ? '-' : ' ');
		for (; i < 16; i++)
			printf("  %c", i == 7 ? '-' : ' ');
		printf("   ");
		for (i = 0; i < n; i++)
			printf("%c", d[i] >= ' ' && d[i] <= '~' ? d[i] : '.');
		printf("\n");
	}
}

void
print_e820_map(struct e820entry *map, int entries)
{
	struct e820entry *m;

	if (entries > 32)
		entries = 32;

	for (m = map; m < &map[entries]; m++) {
		printf("%08lx%08lx - %08lx%08lx ",
			(unsigned long) (m->addr >> 32),
			(unsigned long) (m->addr),
			(unsigned long) ((m->addr+m->size) >> 32),
			(unsigned long) ((m->addr+m->size)));

		switch (m->type) {
		case E820_RAM:
			printf("(RAM)\n"); break;
		case E820_RESERVED:
			printf("(Reserved)\n"); break;
		case E820_ACPI:
			printf("(ACPI Data)\n"); break;
		case E820_NVS:
			printf("(ACPI NVS)\n"); break;
		default:
			printf("(Type %ld)\n", m->type); break;
		}
	}
}

void
dump_dtr(unsigned long addr, unsigned long size)
{
	unsigned long long entry;
	unsigned long base, limit;
	int i;

	for (i = 0; i < size; i += 8) {
		entry = ((unsigned long long *) addr)[i >> 3];
		base = (((entry >> (56-24)) & 0xFF000000) |
			((entry >> (32-16)) & 0x00FF0000) |
			((entry >> (   16)) & 0x0000FFFF));
		limit = (((entry >> (48-16)) & 0x000F0000) |
		         ((entry           ) & 0x0000FFFF));
		if (entry & (1ULL << (23+32))) /* G */
			limit = (limit << 12) | 0xFFF;

		printf("[0x%x] = 0x%08x%08x, base 0x%lx, limit 0x%lx\n", i,
			(unsigned)(entry >> 32), (unsigned)(entry),
			base, limit);
	}
}

void
dump_vmx_context(struct vmx_assist_context *c)
{
	printf("eip 0x%lx, esp 0x%lx, eflags 0x%lx\n",
		(long) c->eip, (long) c->esp, (long) c->eflags);

	printf("cr0 0x%lx, cr3 0x%lx, cr4 0x%lx\n",
		(long)c->cr0, (long)c->cr3, (long)c->cr4);

	printf("idtr: limit 0x%lx, base 0x%lx\n",
		(long)c->idtr_limit, (long)c->idtr_base);

	printf("gdtr: limit 0x%lx, base 0x%lx\n",
		(long)c->gdtr_limit, (long)c->gdtr_base);

	printf("cs: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->cs_sel, (long)c->cs_limit, (long)c->cs_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->cs_arbytes.fields.seg_type,
		c->cs_arbytes.fields.s,
		c->cs_arbytes.fields.dpl,
		c->cs_arbytes.fields.p,
		c->cs_arbytes.fields.avl,
		c->cs_arbytes.fields.default_ops_size,
		c->cs_arbytes.fields.g,
		c->cs_arbytes.fields.null_bit);

	printf("ds: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->ds_sel, (long)c->ds_limit, (long)c->ds_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->ds_arbytes.fields.seg_type,
		c->ds_arbytes.fields.s,
		c->ds_arbytes.fields.dpl,
		c->ds_arbytes.fields.p,
		c->ds_arbytes.fields.avl,
		c->ds_arbytes.fields.default_ops_size,
		c->ds_arbytes.fields.g,
		c->ds_arbytes.fields.null_bit);

	printf("es: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->es_sel, (long)c->es_limit, (long)c->es_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->es_arbytes.fields.seg_type,
		c->es_arbytes.fields.s,
		c->es_arbytes.fields.dpl,
		c->es_arbytes.fields.p,
		c->es_arbytes.fields.avl,
		c->es_arbytes.fields.default_ops_size,
		c->es_arbytes.fields.g,
		c->es_arbytes.fields.null_bit);

	printf("ss: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->ss_sel, (long)c->ss_limit, (long)c->ss_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->ss_arbytes.fields.seg_type,
		c->ss_arbytes.fields.s,
		c->ss_arbytes.fields.dpl,
		c->ss_arbytes.fields.p,
		c->ss_arbytes.fields.avl,
		c->ss_arbytes.fields.default_ops_size,
		c->ss_arbytes.fields.g,
		c->ss_arbytes.fields.null_bit);

	printf("fs: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->fs_sel, (long)c->fs_limit, (long)c->fs_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->fs_arbytes.fields.seg_type,
		c->fs_arbytes.fields.s,
		c->fs_arbytes.fields.dpl,
		c->fs_arbytes.fields.p,
		c->fs_arbytes.fields.avl,
		c->fs_arbytes.fields.default_ops_size,
		c->fs_arbytes.fields.g,
		c->fs_arbytes.fields.null_bit);

	printf("gs: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->gs_sel, (long)c->gs_limit, (long)c->gs_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->gs_arbytes.fields.seg_type,
		c->gs_arbytes.fields.s,
		c->gs_arbytes.fields.dpl,
		c->gs_arbytes.fields.p,
		c->gs_arbytes.fields.avl,
		c->gs_arbytes.fields.default_ops_size,
		c->gs_arbytes.fields.g,
		c->gs_arbytes.fields.null_bit);

	printf("tr: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->tr_sel, (long)c->tr_limit, (long)c->tr_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->tr_arbytes.fields.seg_type,
		c->tr_arbytes.fields.s,
		c->tr_arbytes.fields.dpl,
		c->tr_arbytes.fields.p,
		c->tr_arbytes.fields.avl,
		c->tr_arbytes.fields.default_ops_size,
		c->tr_arbytes.fields.g,
		c->tr_arbytes.fields.null_bit);

	printf("ldtr: sel 0x%lx, limit 0x%lx, base 0x%lx\n",
		(long)c->ldtr_sel, (long)c->ldtr_limit, (long)c->ldtr_base);
	printf("\ttype %d, s %d, dpl %d, p %d, avl %d, ops %d, g %d, nul %d\n",
		c->ldtr_arbytes.fields.seg_type,
		c->ldtr_arbytes.fields.s,
		c->ldtr_arbytes.fields.dpl,
		c->ldtr_arbytes.fields.p,
		c->ldtr_arbytes.fields.avl,
		c->ldtr_arbytes.fields.default_ops_size,
		c->ldtr_arbytes.fields.g,
		c->ldtr_arbytes.fields.null_bit);

	printf("GDTR <0x%lx,0x%lx>:\n",
		(long)c->gdtr_base, (long)c->gdtr_limit);
	dump_dtr(c->gdtr_base, c->gdtr_limit);
}
#endif /* DEBUG */

/*
 * Lightweight printf that doesn't drag in everything under the sun.
 */
int
printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_doprint(putchar, fmt, ap);
	va_end(ap);
	return 0; /* for gcc compat */
}

int
vprintf(const char *fmt, va_list ap)
{
	_doprint(putchar, fmt, ap);
	return 0; /* for gcc compat */
}

void
panic(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_doprint(putchar, fmt, ap);
	putchar('\n');
	va_end(ap);
	halt();
}

unsigned
strlen(const char *s)
{
	const char *q = s;

	while (*s++)
		/* void */;
	return s - q - 1;
}

static void
putchar(int ch)
{
	outb(0xE9, ch);
}

/*
 * A stripped down version of doprint,
 * but still powerful enough for most tasks.
 */
static void
_doprint(void (*put)(int), char const *fmt, va_list ap)
{
	register char *str, c;
	int lflag, zflag, nflag;
	char buffer[17];
	unsigned value;
	int i, slen, pad;

	for ( ; *fmt != '\0'; fmt++) {
		pad = zflag = nflag = lflag = 0;
		if (*fmt == '%') {
			c = *++fmt;
			if (c == '-' || isdigit(c)) {
				if (c == '-') {
					nflag = 1;
					c = *++fmt;
				}
				zflag = c == '0';
				for (pad = 0; isdigit(c); c = *++fmt)
					pad = (pad * 10) + c - '0';
			}
			if (c == 'l') { /* long extension */
				lflag = 1;
				c = *++fmt;
			}
			if (c == 'd' || c == 'u' || c == 'o' || c == 'x') {
				if (lflag)
					value = va_arg(ap, unsigned);
				else
					value = (unsigned) va_arg(ap, unsigned int);
				str = buffer;
				printnum(str, value,
					c == 'o' ? 8 : (c == 'x' ? 16 : 10));
				goto printn;
			} else if (c == 'O' || c == 'D' || c == 'X') {
				value = va_arg(ap, unsigned);
				str = buffer;
				printnum(str, value,
					c == 'O' ? 8 : (c == 'X' ? 16 : 10));
			printn:
				slen = strlen(str);
				for (i = pad - slen; i > 0; i--)
					put(zflag ? '0' : ' ');
				while (*str) put(*str++);
			} else if (c == 's') {
				str = va_arg(ap, char *);
				slen = strlen(str);
				if (nflag == 0)
					for (i = pad - slen; i > 0; i--) put(' ');
				while (*str) put(*str++);
				if (nflag)
					for (i = pad - slen; i > 0; i--) put(' ');
			} else if (c == 'c')
				put(va_arg(ap, int));
			else
				put(*fmt);
		} else
			put(*fmt);
	}
}

static char *
printnum(char *p, unsigned long num, int base)
{
	unsigned long n;

	if ((n = num/base) > 0)
		p = printnum(p, n, base);
	*p++ = "0123456789ABCDEF"[(int)(num % base)];
	*p = '\0';
	return p;
}

void *
memset(void *s, int c, unsigned n)
{
        int t0, t1;

        __asm__ __volatile__ ("cld; rep; stosb"
                : "=&c" (t0), "=&D" (t1)
                : "a" (c), "1" (s), "0" (n)
                : "memory");
        return s;
}

void *
memcpy(void *dest, const void *src, unsigned n)
{
	int t0, t1, t2;

	__asm__ __volatile__(
		"cld\n"
		"rep; movsl\n"
		"testb $2,%b4\n"
		"je 1f\n"
		"movsw\n"
		"1: testb $1,%b4\n"
		"je 2f\n"
		"movsb\n"
		"2:"
		: "=&c" (t0), "=&D" (t1), "=&S" (t2)
		: "0" (n/4), "q" (n), "1" ((long) dest), "2" ((long) src)
		: "memory"
	);
	return dest;
}

