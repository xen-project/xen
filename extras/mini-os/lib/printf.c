/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: printf.c
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Aug 2003
 * 
 * Environment: Xen Minimal OS
 * Description: Library functions for printing
 *              (freebsd port, mainly sys/subr_prf.c)
 *
 ****************************************************************************
 * $Id: c-insert.c,v 1.7 2002/11/08 16:04:34 rn Exp $
 ****************************************************************************
 *
 *-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/libkern/divdi3.c,v 1.6 1999/08/28 00:46:31 peter Exp $
 */

#include <os.h>
#include <types.h>
#include <hypervisor.h>
#include <lib.h>

/****************************************************************************
 * RN: printf family of routines
 * taken mainly from sys/subr_prf.c
 ****************************************************************************/
char const hex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";
#define hex2ascii(hex)  (hex2ascii_data[hex])
#define NBBY    8               /* number of bits in a byte */
#define MAXNBUF    (sizeof(quad_t) * NBBY + 1)

static int kvprintf(char const *fmt, void *arg, int radix, va_list ap);


int
printf(const char *fmt, ...)
{
	va_list ap;
	int retval;
    static char printk_buf[1024];

	va_start(ap, fmt);
	retval = kvprintf(fmt, printk_buf, 10, ap);
    printk_buf[retval] = '\0';
	va_end(ap);
    (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(printk_buf), 
                                printk_buf);
	return retval;
}

int
vprintf(const char *fmt, va_list ap)
{
	int retval;
    static char printk_buf[1024];
	retval = kvprintf(fmt, printk_buf, 10, ap);
    printk_buf[retval] = '\0';
    (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(printk_buf),
                                printk_buf);
	return retval;
}

int
sprintf(char *buf, const char *cfmt, ...)
{
	int retval;
	va_list ap;

	va_start(ap, cfmt);
	retval = kvprintf(cfmt, (void *)buf, 10, ap);
	buf[retval] = '\0';
	va_end(ap);
	return retval;
}

int
vsprintf(char *buf, const char *cfmt, va_list ap)
{
	int retval;

	retval = kvprintf(cfmt, (void *)buf, 10, ap);
	buf[retval] = '\0';
	return retval;
}


/*
 * Put a NUL-terminated ASCII number (base <= 36) in a buffer in reverse
 * order; return an optional length and a pointer to the last character
 * written in the buffer (i.e., the first character of the string).
 * The buffer pointed to by `nbuf' must have length >= MAXNBUF.
 */
static char *
ksprintn(char *nbuf, u_long ul, int base, int *lenp)
{
	char *p;

	p = nbuf;
	*p = '\0';
	do {
		*++p = hex2ascii(ul % base);
	} while (ul /= base);
	if (lenp)
		*lenp = p - nbuf;
	return (p);
}
/* ksprintn, but for a quad_t. */
static char *
ksprintqn(char *nbuf, u_quad_t uq, int base, int *lenp)
{
	char *p;

	p = nbuf;
	*p = '\0';
	do {
		*++p = hex2ascii(uq % base);
	} while (uq /= base);
	if (lenp)
		*lenp = p - nbuf;
	return (p);
}

/*
 * Scaled down version of printf(3).
 *
 * Two additional formats:
 *
 * The format %b is supported to decode error registers.
 * Its usage is:
 *
 *	printf("reg=%b\n", regval, "<base><arg>*");
 *
 * where <base> is the output base expressed as a control character, e.g.
 * \10 gives octal; \20 gives hex.  Each arg is a sequence of characters,
 * the first of which gives the bit number to be inspected (origin 1), and
 * the next characters (up to a control character, i.e. a character <= 32),
 * give the name of the register.  Thus:
 *
 *	kvprintf("reg=%b\n", 3, "\10\2BITTWO\1BITONE\n");
 *
 * would produce output:
 *
 *	reg=3<BITTWO,BITONE>
 *
 * XXX:  %D  -- Hexdump, takes pointer and separator string:
 *		("%6D", ptr, ":")   -> XX:XX:XX:XX:XX:XX
 *		("%*D", len, ptr, " " -> XX XX XX XX ...
 */

/* RN: This normally takes a function for output. 
 * we always print to a string and the use HYPERCALL for write to console */
static int
kvprintf(char const *fmt, void *arg, int radix, va_list ap)
{

#define PCHAR(c) {int cc=(c); *d++ = cc; retval++; }

	char nbuf[MAXNBUF];
	char *p, *q, *d;
	u_char *up;
	int ch, n;
	u_long ul;
	u_quad_t uq;
	int base, lflag, qflag, tmp, width, ladjust, sharpflag, neg, sign, dot;
	int dwidth;
	char padc;
	int retval = 0;

	ul = 0;
	uq = 0;
    d = (char *) arg;

	if (fmt == NULL)
		fmt = "(fmt null)\n";

	if (radix < 2 || radix > 36)
		radix = 10;

	for (;;) {
		padc = ' ';
		width = 0;
		while ((ch = (u_char)*fmt++) != '%') {
			if (ch == '\0') 
				return retval;
			PCHAR(ch);
		}
		qflag = 0; lflag = 0; ladjust = 0; sharpflag = 0; neg = 0;
		sign = 0; dot = 0; dwidth = 0;
reswitch:	switch (ch = (u_char)*fmt++) {
		case '.':
			dot = 1;
			goto reswitch;
		case '#':
			sharpflag = 1;
			goto reswitch;
		case '+':
			sign = 1;
			goto reswitch;
		case '-':
			ladjust = 1;
			goto reswitch;
		case '%':
			PCHAR(ch);
			break;
		case '*':
			if (!dot) {
				width = va_arg(ap, int);
				if (width < 0) {
					ladjust = !ladjust;
					width = -width;
				}
			} else {
				dwidth = va_arg(ap, int);
			}
			goto reswitch;
		case '0':
			if (!dot) {
				padc = '0';
				goto reswitch;
			}
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
				for (n = 0;; ++fmt) {
					n = n * 10 + ch - '0';
					ch = *fmt;
					if (ch < '0' || ch > '9')
						break;
				}
			if (dot)
				dwidth = n;
			else
				width = n;
			goto reswitch;
		case 'b':
			ul = va_arg(ap, int);
			p = va_arg(ap, char *);
			for (q = ksprintn(nbuf, ul, *p++, NULL); *q;)
				PCHAR(*q--);

			if (!ul)
				break;

			for (tmp = 0; *p;) {
				n = *p++;
				if (ul & (1 << (n - 1))) {
					PCHAR(tmp ? ',' : '<');
					for (; (n = *p) > ' '; ++p)
						PCHAR(n);
					tmp = 1;
				} else
					for (; *p > ' '; ++p)
						continue;
			}
			if (tmp)
				PCHAR('>');
			break;
		case 'c':
			PCHAR(va_arg(ap, int));
			break;
		case 'D':
			up = va_arg(ap, u_char *);
			p = va_arg(ap, char *);
			if (!width)
				width = 16;
			while(width--) {
				PCHAR(hex2ascii(*up >> 4));
				PCHAR(hex2ascii(*up & 0x0f));
				up++;
				if (width)
					for (q=p;*q;q++)
						PCHAR(*q);
			}
			break;
		case 'd':
			if (qflag)
				uq = va_arg(ap, quad_t);
			else if (lflag)
				ul = va_arg(ap, long);
			else
				ul = va_arg(ap, int);
			sign = 1;
			base = 10;
			goto number;
		case 'l':
			if (lflag) {
				lflag = 0;
				qflag = 1;
			} else
				lflag = 1;
			goto reswitch;
		case 'o':
			if (qflag)
				uq = va_arg(ap, u_quad_t);
			else if (lflag)
				ul = va_arg(ap, u_long);
			else
				ul = va_arg(ap, u_int);
			base = 8;
			goto nosign;
		case 'p':
			ul = (uintptr_t)va_arg(ap, void *);
			base = 16;
			sharpflag = 0;
            padc  = '0';
            width = sizeof(uintptr_t)*2;
			goto nosign;
		case 'q':
			qflag = 1;
			goto reswitch;
		case 'n':
		case 'r':
			if (qflag)
				uq = va_arg(ap, u_quad_t);
			else if (lflag)
				ul = va_arg(ap, u_long);
			else
				ul = sign ?
				    (u_long)va_arg(ap, int) : va_arg(ap, u_int);
			base = radix;
			goto number;
		case 's':
			p = va_arg(ap, char *);
			if (p == NULL)
				p = "(null)";
			if (!dot)
				n = strlen (p);
			else
				for (n = 0; n < dwidth && p[n]; n++)
					continue;

			width -= n;

			if (!ladjust && width > 0)
				while (width--)
					PCHAR(padc);
			while (n--)
				PCHAR(*p++);
			if (ladjust && width > 0)
				while (width--)
					PCHAR(padc);
			break;
		case 'u':
			if (qflag)
				uq = va_arg(ap, u_quad_t);
			else if (lflag)
				ul = va_arg(ap, u_long);
			else
				ul = va_arg(ap, u_int);
			base = 10;
			goto nosign;
		case 'x':
		case 'X':
			if (qflag)
				uq = va_arg(ap, u_quad_t);
			else if (lflag)
				ul = va_arg(ap, u_long);
			else
				ul = va_arg(ap, u_int);
			base = 16;
			goto nosign;
		case 'z':
			if (qflag)
				uq = va_arg(ap, u_quad_t);
			else if (lflag)
				ul = va_arg(ap, u_long);
			else
				ul = sign ?
				    (u_long)va_arg(ap, int) : va_arg(ap, u_int);
			base = 16;
			goto number;
nosign:			sign = 0;
number:			
			if (qflag) {
				if (sign && (quad_t)uq < 0) {
					neg = 1;
					uq = -(quad_t)uq;
				}
				p = ksprintqn(nbuf, uq, base, &tmp);
			} else {
				if (sign && (long)ul < 0) {
					neg = 1;
					ul = -(long)ul;
				}
				p = ksprintn(nbuf, ul, base, &tmp);
			}
			if (sharpflag && (qflag ? uq != 0 : ul != 0)) {
				if (base == 8)
					tmp++;
				else if (base == 16)
					tmp += 2;
			}
			if (neg)
				tmp++;

			if (!ladjust && width && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);
			if (neg)
				PCHAR('-');
			if (sharpflag && (qflag ? uq != 0 : ul != 0)) {
				if (base == 8) {
					PCHAR('0');
				} else if (base == 16) {
					PCHAR('0');
					PCHAR('x');
				}
			}

			while (*p)
				PCHAR(*p--);

			if (ladjust && width && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);

			break;
		default:
			PCHAR('%');
			if (lflag)
				PCHAR('l');
			PCHAR(ch);
			break;
		}
	}
#undef PCHAR
}

