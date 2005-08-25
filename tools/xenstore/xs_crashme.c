/* Code which randomly corrupts bits going to the daemon.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include "xs.h"
#include "talloc.h"
#include <errno.h>
#include "xenstored.h"

#define XSTEST
#define RAND_FREQ 128 		/* One char in 32 is corrupted. */

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 *
 * Copyright (C) 2003 David S. Miller (davem@redhat.com)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are surely my fault.  -DaveM
 */

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO	0x9e3779b9

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
	u32 a, b, c, len;
	const u8 *k = key;

	len = length;
	a = b = JHASH_GOLDEN_RATIO;
	c = initval;

	while (len >= 12) {
		a += (k[0] +((u32)k[1]<<8) +((u32)k[2]<<16) +((u32)k[3]<<24));
		b += (k[4] +((u32)k[5]<<8) +((u32)k[6]<<16) +((u32)k[7]<<24));
		c += (k[8] +((u32)k[9]<<8) +((u32)k[10]<<16)+((u32)k[11]<<24));

		__jhash_mix(a,b,c);

		k += 12;
		len -= 12;
	}

	c += length;
	switch (len) {
	case 11: c += ((u32)k[10]<<24);
	case 10: c += ((u32)k[9]<<16);
	case 9 : c += ((u32)k[8]<<8);
	case 8 : b += ((u32)k[7]<<24);
	case 7 : b += ((u32)k[6]<<16);
	case 6 : b += ((u32)k[5]<<8);
	case 5 : b += k[4];
	case 4 : a += ((u32)k[3]<<24);
	case 3 : a += ((u32)k[2]<<16);
	case 2 : a += ((u32)k[1]<<8);
	case 1 : a += k[0];
	};

	__jhash_mix(a,b,c);

	return c;
}

/* A special optimized version that handles 1 or more of u32s.
 * The length parameter here is the number of u32s in the key.
 */
static inline u32 jhash2(u32 *k, u32 length, u32 initval)
{
	u32 a, b, c, len;

	a = b = JHASH_GOLDEN_RATIO;
	c = initval;
	len = length;

	while (len >= 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		k += 3; len -= 3;
	}

	c += length * 4;

	switch (len) {
	case 2 : b += k[1];
	case 1 : a += k[0];
	};

	__jhash_mix(a,b,c);

	return c;
}


/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	__jhash_mix(a, b, c);

	return c;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
	return jhash_3words(a, b, 0, initval);
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}

static unsigned int get_randomness(int *state)
{
	return jhash_1word((*state)++, *state * 1103515243);
}

static int state;

/* Lengthening headers is pointless: other end will just wait for more
 * data and timeout.  We merely shorten the length. */
static void corrupt_header(char *output, const struct xsd_sockmsg *msg,
			   unsigned int *next_bit)
{
	struct xsd_sockmsg newmsg = *msg;

	while (*next_bit < sizeof(*msg)) {
		if (newmsg.len)
			newmsg.len = get_randomness(&state) % newmsg.len;
		*next_bit += get_randomness(&state) % RAND_FREQ;
	}
	memcpy(output, &newmsg, sizeof(newmsg));
}

#define read_all_choice read_all
static bool write_all_choice(int fd, const void *data, unsigned int len)
{
	char corrupt_data[len];
	bool ret;
	static unsigned int next_bit;

	if (len == sizeof(struct xsd_sockmsg)
	    && ((unsigned long)data % __alignof__(struct xsd_sockmsg)) == 0)
		corrupt_header(corrupt_data, data, &next_bit);
	else {
		memcpy(corrupt_data, data, len);
		while (next_bit < len * CHAR_BIT) {
			corrupt_data[next_bit/CHAR_BIT]
				^= (1 << (next_bit%CHAR_BIT));
			next_bit += get_randomness(&state) % RAND_FREQ;
		}
	}

	ret = xs_write_all(fd, corrupt_data, len);
	next_bit -= len * CHAR_BIT;
	return ret;
}

#include "xs.c"

static char *random_path(void)
{
	unsigned int i;
	char *ret = NULL;

	if (get_randomness(&state) % 20 == 0)
		return talloc_strdup(NULL, "/");

	for (i = 0; i < 1 || (get_randomness(&state) % 2); i++) {
		ret = talloc_asprintf_append(ret, "/%i", 
					     get_randomness(&state) % 15);
	}
	return ret;
}

static int random_flags(int *state)
{
	switch (get_randomness(state) % 4) {
	case 0:
		return 0;
	case 1:
		return O_CREAT;
	case 2:
		return O_CREAT|O_EXCL;
	default:
		return get_randomness(state);
	}
}

/* Do the next operation, return the results. */
static void do_next_op(struct xs_handle *h, bool verbose)
{
	char *name;
	unsigned int num;

	if (verbose)
		printf("State %i: ", state);

	name = random_path();
	switch (get_randomness(&state) % 9) {
	case 0:
		if (verbose)
			printf("DIR %s\n", name);
		free(xs_directory(h, name, &num));
		break;
	case 1:
		if (verbose)
			printf("READ %s\n", name);
		free(xs_read(h, name, &num));
		break;
	case 2: {
		int flags = random_flags(&state);
		char *contents = talloc_asprintf(NULL, "%i",
						 get_randomness(&state));
		unsigned int len = get_randomness(&state)%(strlen(contents)+1);
		if (verbose)
			printf("WRITE %s %s %.*s\n", name,
			       flags == O_CREAT ? "O_CREAT" 
			       : flags == (O_CREAT|O_EXCL) ? "O_CREAT|O_EXCL"
			       : flags == 0 ? "0" : "CRAPFLAGS",
			       len, contents);
		xs_write(h, name, contents, len, flags);
		break;
	}
	case 3:
		if (verbose)
			printf("MKDIR %s\n", name);
		xs_mkdir(h, name);
		break;
	case 4:
		if (verbose)
			printf("RM %s\n", name);
		xs_rm(h, name);
		break;
	case 5:
		if (verbose)
			printf("GETPERMS %s\n", name);
		free(xs_get_permissions(h, name, &num));
		break;
	case 6: {
		unsigned int i, num = get_randomness(&state)%8;
		struct xs_permissions perms[num];

		if (verbose)
			printf("SETPERMS %s: ", name);
		for (i = 0; i < num; i++) {
			perms[i].id = get_randomness(&state)%8;
			perms[i].perms = get_randomness(&state)%4;
			if (verbose)
				printf("%i%c ", perms[i].id,
				       perms[i].perms == XS_PERM_WRITE ? 'W'
				       : perms[i].perms == XS_PERM_READ ? 'R'
				       : perms[i].perms == 
				       (XS_PERM_READ|XS_PERM_WRITE) ? 'B'
				       : 'N');
		}
		if (verbose)
			printf("\n");
		xs_set_permissions(h, name, perms, num);
		break;
	}
	case 7: {
		if (verbose)
			printf("START %s\n", name);
		xs_transaction_start(h, name);
		break;
	}
	case 8: {
		bool abort = (get_randomness(&state) % 2);

		if (verbose)
			printf("STOP %s\n", abort ? "ABORT" : "COMMIT");
		xs_transaction_end(h, abort);
		break;
	}
	default:
		barf("Impossible randomness");
	}
}

static struct xs_handle *h;
static void alarmed(int sig __attribute__((unused)))
{
	/* We force close on timeout. */
	close(h->fd);
}

static int start_daemon(void)
{
	int fds[2];
	int daemon_pid;

	/* Start daemon. */
	pipe(fds);
	if ((daemon_pid = fork())) {
		/* Child writes PID when its ready: we wait for that. */
		char buffer[20];
		close(fds[1]);
		if (read(fds[0], buffer, sizeof(buffer)) < 0)
			barf("Failed to summon daemon");
		close(fds[0]);
		return daemon_pid;
	} else {
		dup2(fds[1], STDOUT_FILENO);
		close(fds[0]);
#if 1
		execlp("valgrind", "valgrind", "--log-file=/tmp/xs_crashme.vglog", "-q", "./xenstored_test", "--output-pid",
		       "--no-fork", "--trace-file=/tmp/trace", NULL);
#else
		execlp("./xenstored_test", "xenstored_test", "--output-pid",
		       "--no-fork", NULL);
#endif
		exit(1);
	}
}


int main(int argc, char **argv)
{
	unsigned int i;
	int pid;

	if (argc != 3 && argc != 4)
		barf("Usage: xs_crashme <iterations> <seed> [pid]");

	if (argc == 3)
		pid = start_daemon();
	else
		pid = atoi(argv[3]);

	state = atoi(argv[2]);
	h = xs_daemon_open();
	if (!h)
		barf_perror("Opening connection to daemon");
	signal(SIGALRM, alarmed);
	for (i = 0; i < (unsigned)atoi(argv[1]); i++) {
		alarm(1);
		do_next_op(h, false);
		if (i % (atoi(argv[1]) / 72 ?: 1) == 0) {
			printf(".");
			fflush(stdout);
		}
		if (kill(pid, 0) != 0)
			barf_perror("Pinging daemon on iteration %i", i);
		if (h->fd < 0) {
			xs_daemon_close(h);
			h = xs_daemon_open();
			if (!h)
				barf_perror("Connecting on iteration %i", i);
		}
	}
	kill(pid, SIGTERM);
	return 0;
}

