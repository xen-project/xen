/*
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Judy Fischbach <jfisch@cs.pdx.edu>
 *             David Hendricks <cro_marmot@comcast.net>
 *             Josh Triplett <josh@kernel.org>
 *    based on code from Anthony Liguori <aliguori@us.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

/* get curses header from configure */
#include INCLUDE_CURSES_H

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#if defined(__linux__)
#include <linux/kdev_t.h>
#endif

#include <xenstat.h>

#define XENTOP_VERSION "1.0"

#define XENTOP_DISCLAIMER \
"Copyright (C) 2005  International Business Machines  Corp\n"\
"This is free software; see the source for copying conditions.There is NO\n"\
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
#define XENTOP_BUGSTO "Report bugs to <xen-devel@lists.xen.org>.\n"

#define _GNU_SOURCE
#include <getopt.h>

#if !defined(__GNUC__) && !defined(__GNUG__)
#define __attribute__(arg) /* empty */
#endif

#define KEY_ESCAPE '\x1B'
#define KEY_REPAINT '\x0C'

#ifdef HOST_SunOS
/* Old curses library on Solaris takes non-const strings. Also, ERR interferes
 * with curse's definition.
 */
#undef ERR
#define ERR (-1)
#define curses_str_t char *
#else
#define curses_str_t const char *
#endif

#define INT_FIELD_WIDTH(n) ((unsigned int)(log10(n) + 1))

/*
 * Function prototypes
 */
/* Utility functions */
static void usage(const char *);
static void version(void);
static void cleanup(void);
static void fail(const char *);
static int current_row(void);
static int lines(void);
static void print(const char *, ...) __attribute__((format(printf,1,2)));
static void attr_addstr(int attr, const char *str);
static void set_delay(char *value);
static void set_prompt(char *new_prompt, void (*func)(char *));
static int handle_key(int);
static int compare(unsigned long long, unsigned long long);
static int compare_domains(xenstat_domain **, xenstat_domain **);
static unsigned long long tot_net_bytes( xenstat_domain *, int);
static unsigned long long tot_vbd_reqs( xenstat_domain *, int);

/* Field functions */
static int compare_state(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_state(xenstat_domain *domain);
static int compare_cpu(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_cpu(xenstat_domain *domain);
static int compare_cpu_pct(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_cpu_pct(xenstat_domain *domain);
static int compare_mem(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_mem(xenstat_domain *domain);
static void print_mem_pct(xenstat_domain *domain);
static int compare_maxmem(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_maxmem(xenstat_domain *domain);
static void print_max_pct(xenstat_domain *domain);
static int compare_vcpus(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vcpus(xenstat_domain *domain);
static int compare_nets(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_nets(xenstat_domain *domain);
static int compare_net_tx(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_net_tx(xenstat_domain *domain);
static int compare_net_rx(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_net_rx(xenstat_domain *domain);
static int compare_ssid(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_ssid(xenstat_domain *domain);
static int compare_name(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_name(xenstat_domain *domain);
static int compare_vbds(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vbds(xenstat_domain *domain);
static int compare_vbd_oo(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vbd_oo(xenstat_domain *domain);
static int compare_vbd_rd(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vbd_rd(xenstat_domain *domain);
static int compare_vbd_wr(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vbd_wr(xenstat_domain *domain);
static int compare_vbd_rsect(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vbd_rsect(xenstat_domain *domain);
static int compare_vbd_wsect(xenstat_domain *domain1, xenstat_domain *domain2);
static void print_vbd_wsect(xenstat_domain *domain);
static void reset_field_widths(void);
static void adjust_field_widths(xenstat_domain *domain);

/* Section printing functions */
static void do_summary(void);
static void do_header(void);
static void do_bottom_line(void);
static void do_domain(xenstat_domain *);
static void do_vcpu(xenstat_domain *);
static void do_network(xenstat_domain *);
static void do_vbd(xenstat_domain *);
static void top(void);

/* Field types */
typedef enum field_id {
	FIELD_DOMID,
	FIELD_NAME,
	FIELD_STATE,
	FIELD_CPU,
	FIELD_CPU_PCT,
	FIELD_MEM,
	FIELD_MEM_PCT,
	FIELD_MAXMEM,
	FIELD_MAX_PCT,
	FIELD_VCPUS,
	FIELD_NETS,
	FIELD_NET_TX,
	FIELD_NET_RX,
	FIELD_VBDS,
	FIELD_VBD_OO,
	FIELD_VBD_RD,
	FIELD_VBD_WR,
	FIELD_VBD_RSECT,
	FIELD_VBD_WSECT,
	FIELD_SSID
} field_id;

typedef struct field {
	field_id num;
	const char *header;
	unsigned int default_width;
	int (*compare)(xenstat_domain *domain1, xenstat_domain *domain2);
	void (*print)(xenstat_domain *domain);
} field;

field fields[] = {
	{ FIELD_NAME,      "NAME",      10, compare_name,      print_name    },
	{ FIELD_STATE,     "STATE",      6, compare_state,     print_state   },
	{ FIELD_CPU,       "CPU(sec)",  10, compare_cpu,       print_cpu     },
	{ FIELD_CPU_PCT,   "CPU(%)",     6, compare_cpu_pct,   print_cpu_pct },
	{ FIELD_MEM,       "MEM(k)",    10, compare_mem,       print_mem     },
	{ FIELD_MEM_PCT,   "MEM(%)",     6, compare_mem,       print_mem_pct },
	{ FIELD_MAXMEM,    "MAXMEM(k)", 10, compare_maxmem,    print_maxmem  },
	{ FIELD_MAX_PCT,   "MAXMEM(%)",  9, compare_maxmem,    print_max_pct },
	{ FIELD_VCPUS,     "VCPUS",      5, compare_vcpus,     print_vcpus   },
	{ FIELD_NETS,      "NETS",       4, compare_nets,      print_nets    },
	{ FIELD_NET_TX,    "NETTX(k)",   8, compare_net_tx,    print_net_tx  },
	{ FIELD_NET_RX,    "NETRX(k)",   8, compare_net_rx,    print_net_rx  },
	{ FIELD_VBDS,      "VBDS",       4, compare_vbds,      print_vbds    },
	{ FIELD_VBD_OO,    "VBD_OO",     8, compare_vbd_oo,    print_vbd_oo  },
	{ FIELD_VBD_RD,    "VBD_RD",     8, compare_vbd_rd,    print_vbd_rd  },
	{ FIELD_VBD_WR,    "VBD_WR",     8, compare_vbd_wr,    print_vbd_wr  },
	{ FIELD_VBD_RSECT, "VBD_RSECT", 10, compare_vbd_rsect, print_vbd_rsect  },
	{ FIELD_VBD_WSECT, "VBD_WSECT", 10, compare_vbd_wsect, print_vbd_wsect  },
	{ FIELD_SSID,      "SSID",       4, compare_ssid,      print_ssid    }
};

const unsigned int NUM_FIELDS = sizeof(fields)/sizeof(field);

/* Globals */
struct timeval curtime, oldtime;
xenstat_handle *xhandle = NULL;
xenstat_node *prev_node = NULL;
xenstat_node *cur_node = NULL;
field_id sort_field = FIELD_DOMID;
unsigned int first_domain_index = 0;
unsigned int delay = 3;
unsigned int batch = 0;
unsigned int loop = 1;
unsigned int iterations = 0;
int show_vcpus = 0;
int show_networks = 0;
int show_vbds = 0;
int show_tmem = 0;
int repeat_header = 0;
int show_full_name = 0;
#define PROMPT_VAL_LEN 80
char *prompt = NULL;
char prompt_val[PROMPT_VAL_LEN];
int prompt_val_len = 0;
void (*prompt_complete_func)(char *);

static WINDOW *cwin;

/*
 * Function definitions
 */

/* Utility functions */

/* Print usage message, using given program name */
static void usage(const char *program)
{
	printf("Usage: %s [OPTION]\n"
	       "Displays ongoing information about xen vm resources \n\n"
	       "-h, --help           display this help and exit\n"
	       "-V, --version        output version information and exit\n"
	       "-d, --delay=SECONDS  seconds between updates (default 3)\n"
	       "-n, --networks       output vif network data\n"
	       "-x, --vbds           output vbd block device data\n"
	       "-r, --repeat-header  repeat table header before each domain\n"
	       "-v, --vcpus          output vcpu data\n"
	       "-b, --batch	     output in batch mode, no user input accepted\n"
	       "-i, --iterations     number of iterations before exiting\n"
	       "-f, --full-name      output the full domain name (not truncated)\n"
	       "\n" XENTOP_BUGSTO,
	       program);
	return;
}

/* Print program version information */
static void version(void)
{
	printf("xentop " XENTOP_VERSION "\n"
	       "Written by Judy Fischbach, David Hendricks, Josh Triplett\n"
	       "\n" XENTOP_DISCLAIMER);
}

/* Clean up any open resources */
static void cleanup(void)
{
	if(cwin != NULL && !isendwin())
		endwin();
	if(prev_node != NULL)
		xenstat_free_node(prev_node);
	if(cur_node != NULL)
		xenstat_free_node(cur_node);
	if(xhandle != NULL)
		xenstat_uninit(xhandle);
}

/* Display the given message and gracefully exit */
static void fail(const char *str)
{
	if(cwin != NULL && !isendwin())
		endwin();
	fprintf(stderr, "%s", str);
	exit(1);
}

/* Return the row containing the cursor. */
static int current_row(void)
{
	int y, x;
	getyx(stdscr, y, x);
	return y;
}

/* Return the number of lines on the screen. */
static int lines(void)
{
	int y, x;
	getmaxyx(stdscr, y, x);
	return y;
}

/* printf-style print function which calls printw, but only if the cursor is
 * not on the last line. */
static void print(const char *fmt, ...)
{
	va_list args;

	if (!batch) {
		if((current_row() < lines()-1)) {
			va_start(args, fmt);
			vwprintw(stdscr, (curses_str_t)fmt, args);
			va_end(args);
		}
	} else {
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
	}
}

static void xentop_attron(int attr)
{
	if (!batch)
		attron(attr);
}

static void xentop_attroff(int attr)
{
	if (!batch)
		attroff(attr);
}

/* Print a string with the given attributes set. */
static void attr_addstr(int attr, const char *str)
{
	xentop_attron(attr);
	addstr((curses_str_t)str);
	xentop_attroff(attr);
}

/* Handle setting the delay from the user-supplied value in prompt_val */
static void set_delay(char *value)
{
	int new_delay;
	new_delay = atoi(value);
	if(new_delay > 0)
		delay = new_delay;
}

/* Enable prompting mode with the given prompt string; call the given function
 * when a value is available. */
static void set_prompt(char *new_prompt, void (*func)(char *))
{
	prompt = new_prompt;
	prompt_val[0] = '\0';
	prompt_val_len = 0;
	prompt_complete_func = func;
}

/* Handle user input, return 0 if the program should quit, or 1 if not */
static int handle_key(int ch)
{
	if(prompt == NULL) {
		/* Not prompting for input; handle interactive commands */
		switch(ch) {
		case 'n': case 'N':
			show_networks ^= 1;
			break;
		case 'b': case 'B':
			show_vbds ^= 1;
			break;
		case 't': case 'T':
			show_tmem ^= 1;
			break;
		case 'r': case 'R':
			repeat_header ^= 1;
			break;
		case 's': case 'S':
			sort_field = (sort_field + 1) % NUM_FIELDS;
			break;
		case 'v': case 'V':
			show_vcpus ^= 1;
			break;
		case KEY_DOWN:
			first_domain_index++;
			break;
		case KEY_UP:
			if(first_domain_index > 0)
				first_domain_index--;
			break;
		case 'd': case 'D':
			set_prompt("Delay(sec)", set_delay);
			break;
		case KEY_REPAINT:
			clear();
			break;
		case 'q': case 'Q': case KEY_ESCAPE:
			return 0;
		}
	} else {
		/* Prompting for input; handle line editing */
		switch(ch) {
		case '\r':
			prompt_complete_func(prompt_val);
			set_prompt(NULL, NULL);
			break;
		case KEY_ESCAPE:
			set_prompt(NULL, NULL);
			break;
		case KEY_BACKSPACE:
			if(prompt_val_len > 0)
				prompt_val[--prompt_val_len] = '\0';
                        break;
		default:
			if((prompt_val_len+1) < PROMPT_VAL_LEN
			   && isprint(ch)) {
				prompt_val[prompt_val_len++] = (char)ch;
				prompt_val[prompt_val_len] = '\0';
			}
		}
	}

	return 1;
}

/* Compares two integers, returning -1,0,1 for <,=,> */
static int compare(unsigned long long i1, unsigned long long i2)
{
	if(i1 < i2)
		return -1;
	if(i1 > i2)
		return 1;
	return 0;
}

/* Comparison function for use with qsort.  Compares two domains using the
 * current sort field. */
static int compare_domains(xenstat_domain **domain1, xenstat_domain **domain2)
{
	return fields[sort_field].compare(*domain1, *domain2);
}

/* Field functions */

/* Compare domain names, returning -1,0,1 for <,=,> */
int compare_name(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return strcasecmp(xenstat_domain_name(domain1), xenstat_domain_name(domain2));
}

/* Prints domain name */
void print_name(xenstat_domain *domain)
{
	if(show_full_name)
		print("%*s", fields[FIELD_NAME-1].default_width, xenstat_domain_name(domain));
	else
		print("%10.10s", xenstat_domain_name(domain));
}

struct {
	unsigned int (*get)(xenstat_domain *);
	char ch;
} state_funcs[] = {
	{ xenstat_domain_dying,    'd' },
	{ xenstat_domain_shutdown, 's' },
	{ xenstat_domain_blocked,  'b' },
	{ xenstat_domain_crashed,  'c' },
	{ xenstat_domain_paused,   'p' },
	{ xenstat_domain_running,  'r' }
};
const unsigned int NUM_STATES = sizeof(state_funcs)/sizeof(*state_funcs);

/* Compare states of two domains, returning -1,0,1 for <,=,> */
static int compare_state(xenstat_domain *domain1, xenstat_domain *domain2)
{
	unsigned int i, d1s, d2s;
	for(i = 0; i < NUM_STATES; i++) {
		d1s = state_funcs[i].get(domain1);
		d2s = state_funcs[i].get(domain2);
		if(d1s && !d2s)
			return -1;
		if(d2s && !d1s)
			return 1;
	}
	return 0;
}

/* Prints domain state in abbreviated letter format */
static void print_state(xenstat_domain *domain)
{
	unsigned int i;
	for(i = 0; i < NUM_STATES; i++)
		print("%c", state_funcs[i].get(domain) ? state_funcs[i].ch
		                                       : '-');
}

/* Compares cpu usage of two domains, returning -1,0,1 for <,=,> */
static int compare_cpu(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(xenstat_domain_cpu_ns(domain1),
			xenstat_domain_cpu_ns(domain2));
}

/* Prints domain cpu usage in seconds */
static void print_cpu(xenstat_domain *domain)
{
	print("%10llu", xenstat_domain_cpu_ns(domain)/1000000000);
}

/* Computes the CPU percentage used for a specified domain */
static double get_cpu_pct(xenstat_domain *domain)
{
	xenstat_domain *old_domain;
	double us_elapsed;

	/* Can't calculate CPU percentage without a previous sample. */
	if(prev_node == NULL)
		return 0.0;

	old_domain = xenstat_node_domain(prev_node, xenstat_domain_id(domain));
	if(old_domain == NULL)
		return 0.0;

	/* Calculate the time elapsed in microseconds */
	us_elapsed = ((curtime.tv_sec-oldtime.tv_sec)*1000000.0
		      +(curtime.tv_usec - oldtime.tv_usec));

	/* In the following, nanoseconds must be multiplied by 1000.0 to
	 * convert to microseconds, then divided by 100.0 to get a percentage,
	 * resulting in a multiplication by 10.0 */
	return ((xenstat_domain_cpu_ns(domain)
		 -xenstat_domain_cpu_ns(old_domain))/10.0)/us_elapsed;
}

static int compare_cpu_pct(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(get_cpu_pct(domain1), get_cpu_pct(domain2));
}

/* Prints cpu percentage statistic */
static void print_cpu_pct(xenstat_domain *domain)
{
	print("%6.1f", get_cpu_pct(domain));
}

/* Compares current memory of two domains, returning -1,0,1 for <,=,> */
static int compare_mem(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(xenstat_domain_cur_mem(domain1),
	                xenstat_domain_cur_mem(domain2));
}

/* Prints current memory statistic */
static void print_mem(xenstat_domain *domain)
{
	print("%10llu", xenstat_domain_cur_mem(domain)/1024);
}

/* Prints memory percentage statistic, ratio of current domain memory to total
 * node memory */
static void print_mem_pct(xenstat_domain *domain)
{
	print("%6.1f", (double)xenstat_domain_cur_mem(domain) /
	               (double)xenstat_node_tot_mem(cur_node) * 100);
}

/* Compares maximum memory of two domains, returning -1,0,1 for <,=,> */
static int compare_maxmem(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(xenstat_domain_max_mem(domain1),
	                xenstat_domain_max_mem(domain2));
}

/* Prints maximum domain memory statistic in KB */
static void print_maxmem(xenstat_domain *domain)
{
	unsigned long long max_mem = xenstat_domain_max_mem(domain);
	if(max_mem == ((unsigned long long)-1))
		print("%10s", "no limit");
	else
		print("%10llu", max_mem/1024);
}

/* Prints memory percentage statistic, ratio of current domain memory to total
 * node memory */
static void print_max_pct(xenstat_domain *domain)
{
	if (xenstat_domain_max_mem(domain) == (unsigned long long)-1)
		print("%9s", "n/a");
	else
		print("%9.1f", (double)xenstat_domain_max_mem(domain) /
		               (double)xenstat_node_tot_mem(cur_node) * 100);
}

/* Compares number of virtual CPUs of two domains, returning -1,0,1 for
 * <,=,> */
static int compare_vcpus(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(xenstat_domain_num_vcpus(domain1),
	                xenstat_domain_num_vcpus(domain2));
}

/* Prints number of virtual CPUs statistic */
static void print_vcpus(xenstat_domain *domain)
{
	print("%5u", xenstat_domain_num_vcpus(domain));
}

/* Compares number of virtual networks of two domains, returning -1,0,1 for
 * <,=,> */
static int compare_nets(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(xenstat_domain_num_networks(domain1),
	                xenstat_domain_num_networks(domain2));
}

/* Prints number of virtual networks statistic */
static void print_nets(xenstat_domain *domain)
{
	print("%4u", xenstat_domain_num_networks(domain));
}

/* Compares number of total network tx bytes of two domains, returning -1,0,1
 * for <,=,> */
static int compare_net_tx(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(tot_net_bytes(domain1, FALSE),
	                tot_net_bytes(domain2, FALSE));
}

/* Prints number of total network tx bytes statistic */
static void print_net_tx(xenstat_domain *domain)
{
	print("%*llu", fields[FIELD_NET_TX-1].default_width, tot_net_bytes(domain, FALSE)/1024);
}

/* Compares number of total network rx bytes of two domains, returning -1,0,1
 * for <,=,> */
static int compare_net_rx(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(tot_net_bytes(domain1, TRUE),
	                tot_net_bytes(domain2, TRUE));
}

/* Prints number of total network rx bytes statistic */
static void print_net_rx(xenstat_domain *domain)
{
	print("%*llu", fields[FIELD_NET_RX-1].default_width, tot_net_bytes(domain, TRUE)/1024);
}

/* Gets number of total network bytes statistic, if rx true, then rx bytes
 * otherwise tx bytes
 */
static unsigned long long tot_net_bytes(xenstat_domain *domain, int rx_flag)
{
	int i = 0;
	xenstat_network *network;
	unsigned num_networks = 0;
	unsigned long long total = 0;

	/* How many networks? */
	num_networks = xenstat_domain_num_networks(domain);

	/* Dump information for each network */
	for (i=0; i < num_networks; i++) {
		/* Next get the network information */
		network = xenstat_domain_network(domain,i);
		if (rx_flag)
			total += xenstat_network_rbytes(network);
		else
			total += xenstat_network_tbytes(network);
	}

	return total;
}

/* Compares number of virtual block devices of two domains,
   returning -1,0,1 for * <,=,> */
static int compare_vbds(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(xenstat_domain_num_vbds(domain1),
	                xenstat_domain_num_vbds(domain2));
}

/* Prints number of virtual block devices statistic */
static void print_vbds(xenstat_domain *domain)
{
	print("%4u", xenstat_domain_num_vbds(domain));
}

/* Compares number of total VBD OO requests of two domains,
   returning -1,0,1 * for <,=,> */
static int compare_vbd_oo(xenstat_domain *domain1, xenstat_domain *domain2)
{
  return -compare(tot_vbd_reqs(domain1, FIELD_VBD_OO),
		  tot_vbd_reqs(domain2, FIELD_VBD_OO));
}

/* Prints number of total VBD OO requests statistic */
static void print_vbd_oo(xenstat_domain *domain)
{
	print("%8llu", tot_vbd_reqs(domain, FIELD_VBD_OO));
}

/* Compares number of total VBD READ requests of two domains,
   returning -1,0,1 * for <,=,> */
static int compare_vbd_rd(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(tot_vbd_reqs(domain1, FIELD_VBD_RD),
			tot_vbd_reqs(domain2, FIELD_VBD_RD));
}

/* Prints number of total VBD READ requests statistic */
static void print_vbd_rd(xenstat_domain *domain)
{
	print("%*llu", fields[FIELD_VBD_RD-1].default_width, tot_vbd_reqs(domain, FIELD_VBD_RD));
}

/* Compares number of total VBD WRITE requests of two domains,
   returning -1,0,1 * for <,=,> */
static int compare_vbd_wr(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(tot_vbd_reqs(domain1, FIELD_VBD_WR),
			tot_vbd_reqs(domain2, FIELD_VBD_WR));
}

/* Prints number of total VBD WRITE requests statistic */
static void print_vbd_wr(xenstat_domain *domain)
{
	print("%*llu", fields[FIELD_VBD_WR-1].default_width, tot_vbd_reqs(domain, FIELD_VBD_WR));
}

/* Compares number of total VBD READ sectors of two domains,
   returning -1,0,1 * for <,=,> */
static int compare_vbd_rsect(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(tot_vbd_reqs(domain1, FIELD_VBD_RSECT),
			tot_vbd_reqs(domain2, FIELD_VBD_RSECT));
}

/* Prints number of total VBD READ sectors statistic */
static void print_vbd_rsect(xenstat_domain *domain)
{
	print("%*llu", fields[FIELD_VBD_RSECT-1].default_width, tot_vbd_reqs(domain, FIELD_VBD_RSECT));
}

/* Compares number of total VBD WRITE sectors of two domains,
   returning -1,0,1 * for <,=,> */
static int compare_vbd_wsect(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return -compare(tot_vbd_reqs(domain1, FIELD_VBD_WSECT),
			tot_vbd_reqs(domain2, FIELD_VBD_WSECT));
}

/* Prints number of total VBD WRITE sectors statistic */
static void print_vbd_wsect(xenstat_domain *domain)
{
	print("%*llu", fields[FIELD_VBD_WSECT-1].default_width, tot_vbd_reqs(domain, FIELD_VBD_WSECT));
}


/* Gets number of total VBD requests statistic, 
 *   if flag is FIELD_VBD_OO, then OO requests,
 *   if flag is FIELD_VBD_RD, then READ requests,
 *   if flag is FIELD_VBD_WR, then WRITE requests,
 *   if flag is FIELD_VBD_RSECT, then READ sectors,
 *   if flag is FIELD_VBD_WSECT, then WRITE sectors.
 */
static unsigned long long tot_vbd_reqs(xenstat_domain *domain, int flag)
{
	int i = 0;
	xenstat_vbd *vbd;
	unsigned num_vbds = 0;
	unsigned long long total = 0;
	
	num_vbds = xenstat_domain_num_vbds(domain);
	
	for ( i=0 ; i < num_vbds ; i++) {
		vbd = xenstat_domain_vbd(domain,i);
		switch(flag) {
		case FIELD_VBD_OO:
			total += xenstat_vbd_oo_reqs(vbd);
			break;
		case FIELD_VBD_RD:
			total += xenstat_vbd_rd_reqs(vbd);
			break;
		case FIELD_VBD_WR:
			total += xenstat_vbd_wr_reqs(vbd);
			break;
		case FIELD_VBD_RSECT:
			total += xenstat_vbd_rd_sects(vbd);
			break;
		case FIELD_VBD_WSECT:
			total += xenstat_vbd_wr_sects(vbd);
			break;
		default:
			break;
		}
	}
	
	return total;
}

/* Compares security id (ssid) of two domains, returning -1,0,1 for <,=,> */
static int compare_ssid(xenstat_domain *domain1, xenstat_domain *domain2)
{
	return compare(xenstat_domain_ssid(domain1),
		       xenstat_domain_ssid(domain2));
}

/* Prints ssid statistic */
static void print_ssid(xenstat_domain *domain)
{
	print("%4u", xenstat_domain_ssid(domain));
}

/* Resets default_width for fields with potentially large numbers */
void reset_field_widths(void)
{
	fields[FIELD_NET_TX-1].default_width = 8;
	fields[FIELD_NET_RX-1].default_width = 8;
	fields[FIELD_VBD_RD-1].default_width = 8;
	fields[FIELD_VBD_WR-1].default_width = 8;
	fields[FIELD_VBD_RSECT-1].default_width = 10;
	fields[FIELD_VBD_WSECT-1].default_width = 10;
}

/* Adjusts default_width for fields with potentially large numbers */
void adjust_field_widths(xenstat_domain *domain)
{
	unsigned int length;

	if (show_full_name) {
		length = strlen(xenstat_domain_name(domain));
		if (length > fields[FIELD_NAME-1].default_width)
			fields[FIELD_NAME-1].default_width = length;
	}

	length = INT_FIELD_WIDTH((tot_net_bytes(domain, FALSE)/1024) + 1);
	if (length > fields[FIELD_NET_TX-1].default_width)
		fields[FIELD_NET_TX-1].default_width = length;

	length = INT_FIELD_WIDTH((tot_net_bytes(domain, TRUE)/1024) + 1);
	if (length > fields[FIELD_NET_RX-1].default_width)
		fields[FIELD_NET_RX-1].default_width = length;

	length = INT_FIELD_WIDTH((tot_vbd_reqs(domain, FIELD_VBD_RD)) + 1);
	if (length > fields[FIELD_VBD_RD-1].default_width)
		fields[FIELD_VBD_RD-1].default_width = length;

	length = INT_FIELD_WIDTH((tot_vbd_reqs(domain, FIELD_VBD_WR)) + 1);
	if (length > fields[FIELD_VBD_WR-1].default_width)
		fields[FIELD_VBD_WR-1].default_width = length;

	length = INT_FIELD_WIDTH((tot_vbd_reqs(domain, FIELD_VBD_RSECT)) + 1);
	if (length > fields[FIELD_VBD_RSECT-1].default_width)
		fields[FIELD_VBD_RSECT-1].default_width = length;

	length = INT_FIELD_WIDTH((tot_vbd_reqs(domain, FIELD_VBD_WSECT)) + 1);
	if (length > fields[FIELD_VBD_WSECT-1].default_width)
		fields[FIELD_VBD_WSECT-1].default_width = length;
}


/* Section printing functions */
/* Prints the top summary, above the domain table */
void do_summary(void)
{
#define TIME_STR_LEN 9
	const char *TIME_STR_FORMAT = "%H:%M:%S";
	char time_str[TIME_STR_LEN];
	const char *ver_str;
	unsigned run = 0, block = 0, pause = 0,
	         crash = 0, dying = 0, shutdown = 0;
	unsigned i, num_domains = 0;
	unsigned long long used = 0;
	long freeable_mb = 0;
	xenstat_domain *domain;
	time_t curt;

	/* Print program name, current time, and number of domains */
	curt = curtime.tv_sec;
	strftime(time_str, TIME_STR_LEN, TIME_STR_FORMAT, localtime(&curt));
	num_domains = xenstat_node_num_domains(cur_node);
	ver_str = xenstat_node_xen_version(cur_node);
	print("xentop - %s   Xen %s\n", time_str, ver_str);

	/* Tabulate what states domains are in for summary */
	for (i=0; i < num_domains; i++) {
		domain = xenstat_node_domain_by_index(cur_node,i);
		if (xenstat_domain_running(domain)) run++;
		else if (xenstat_domain_blocked(domain)) block++;
		else if (xenstat_domain_paused(domain)) pause++;
		else if (xenstat_domain_shutdown(domain)) shutdown++;
		else if (xenstat_domain_crashed(domain)) crash++;
		else if (xenstat_domain_dying(domain)) dying++;
	}

	print("%u domains: %u running, %u blocked, %u paused, "
	      "%u crashed, %u dying, %u shutdown \n",
	      num_domains, run, block, pause, crash, dying, shutdown);

	used = xenstat_node_tot_mem(cur_node)-xenstat_node_free_mem(cur_node);
	freeable_mb = xenstat_node_freeable_mb(cur_node);

	/* Dump node memory and cpu information */
	if ( freeable_mb <= 0 )
	     print("Mem: %lluk total, %lluk used, %lluk free    ",
	      xenstat_node_tot_mem(cur_node)/1024, used/1024,
	      xenstat_node_free_mem(cur_node)/1024);
	else
	     print("Mem: %lluk total, %lluk used, %lluk free, %ldk freeable, ",
	      xenstat_node_tot_mem(cur_node)/1024, used/1024,
	      xenstat_node_free_mem(cur_node)/1024, freeable_mb*1024);
	print("CPUs: %u @ %lluMHz\n",
	      xenstat_node_num_cpus(cur_node),
	      xenstat_node_cpu_hz(cur_node)/1000000);
}

/* Display the top header for the domain table */
void do_header(void)
{
	field_id i;

	/* Turn on REVERSE highlight attribute for headings */
	xentop_attron(A_REVERSE);
	for(i = 0; i < NUM_FIELDS; i++) {
		if (i != 0)
			print(" ");
		/* The BOLD attribute is turned on for the sort column */
		if (i == sort_field)
			xentop_attron(A_BOLD);
		print("%*s", fields[i].default_width, fields[i].header);
		if (i == sort_field)
			xentop_attroff(A_BOLD);
	}
	xentop_attroff(A_REVERSE);
	print("\n");
}

/* Displays bottom status line or current prompt */
void do_bottom_line(void)
{
	move(lines()-1, 2);

	if (prompt != NULL) {
		printw("%s: %s", prompt, prompt_val);
	} else {
		addch(A_REVERSE | 'D'); addstr("elay  ");

		/* network */
		addch(A_REVERSE | 'N');
		attr_addstr(show_networks ? COLOR_PAIR(1) : 0, "etworks");
		addstr("  ");
		
		/* VBDs */
		attr_addstr(show_vbds ? COLOR_PAIR(1) : 0, "v");
		addch(A_REVERSE | 'B');
		attr_addstr(show_vbds ? COLOR_PAIR(1) : 0, "ds");
		addstr("  ");

		/* tmem */
		addch(A_REVERSE | 'T');
		attr_addstr(show_tmem ? COLOR_PAIR(1) : 0, "mem");
		addstr("  ");


		/* vcpus */
		addch(A_REVERSE | 'V');
		attr_addstr(show_vcpus ? COLOR_PAIR(1) : 0, "CPUs");
		addstr("  ");

		/* repeat */
		addch(A_REVERSE | 'R');
		attr_addstr(repeat_header ? COLOR_PAIR(1) : 0, "epeat header");
		addstr("  ");

		/* sort order */
		addch(A_REVERSE | 'S'); addstr("ort order  ");

		addch(A_REVERSE | 'Q'); addstr("uit  ");
	}
}

/* Prints Domain information */
void do_domain(xenstat_domain *domain)
{
	unsigned int i;
	for (i = 0; i < NUM_FIELDS; i++) {
		if (i != 0)
			print(" ");
		if (i == sort_field)
			xentop_attron(A_BOLD);
		fields[i].print(domain);
		if (i == sort_field)
			xentop_attroff(A_BOLD);
	}
	print("\n");
}

/* Output all vcpu information */
void do_vcpu(xenstat_domain *domain)
{
	int i = 0;
	unsigned num_vcpus = 0;
	xenstat_vcpu *vcpu;

	print("VCPUs(sec): ");

	num_vcpus = xenstat_domain_num_vcpus(domain);

	/* for all online vcpus dump out values */
	for (i=0; i< num_vcpus; i++) {
		vcpu = xenstat_domain_vcpu(domain,i);

		if (xenstat_vcpu_online(vcpu) > 0) {
			if (i != 0 && (i%5)==0)
				print("\n        ");
			print(" %2u: %10llus", i, 
					xenstat_vcpu_ns(vcpu)/1000000000);
		}
	}
	print("\n");
}

/* Output all network information */
void do_network(xenstat_domain *domain)
{
	int i = 0;
	xenstat_network *network;
	unsigned num_networks = 0;

	/* How many networks? */
	num_networks = xenstat_domain_num_networks(domain);

	/* Dump information for each network */
	for (i=0; i < num_networks; i++) {
		/* Next get the network information */
		network = xenstat_domain_network(domain,i);

		print("Net%d RX: %8llubytes %8llupkts %8lluerr %8lludrop  ",
		      i,
		      xenstat_network_rbytes(network),
		      xenstat_network_rpackets(network),
		      xenstat_network_rerrs(network),
		      xenstat_network_rdrop(network));

		print("TX: %8llubytes %8llupkts %8lluerr %8lludrop\n",
		      xenstat_network_tbytes(network),
		      xenstat_network_tpackets(network),
		      xenstat_network_terrs(network),
		      xenstat_network_tdrop(network));
	}
}


/* Output all VBD information */
void do_vbd(xenstat_domain *domain)
{
	int i = 0;
	xenstat_vbd *vbd;
	unsigned num_vbds = 0;

	const char *vbd_type[] = {
		"Unidentified",           /* number 0 */
		"BlkBack",           /* number 1 */
		"BlkTap",            /* number 2 */
	};
	
	num_vbds = xenstat_domain_num_vbds(domain);

	for (i=0 ; i< num_vbds; i++) {
		char details[20];

		vbd = xenstat_domain_vbd(domain,i);

#if !defined(__linux__)
		details[0] = '\0';
#else
		snprintf(details, 20, "[%2x:%2x] ",
			 MAJOR(xenstat_vbd_dev(vbd)),
			 MINOR(xenstat_vbd_dev(vbd)));
#endif

		print("VBD %s %4d %s OO: %8llu   RD: %8llu   WR: %8llu   RSECT: %10llu   WSECT: %10llu\n",
		      vbd_type[xenstat_vbd_type(vbd)],
		      xenstat_vbd_dev(vbd), details,
		      xenstat_vbd_oo_reqs(vbd),
		      xenstat_vbd_rd_reqs(vbd),
		      xenstat_vbd_wr_reqs(vbd),
		      xenstat_vbd_rd_sects(vbd),
		      xenstat_vbd_wr_sects(vbd));
	}
}

/* Output all tmem information */
void do_tmem(xenstat_domain *domain)
{
	xenstat_tmem *tmem = xenstat_domain_tmem(domain);
	unsigned long long curr_eph_pages = xenstat_tmem_curr_eph_pages(tmem);
	unsigned long long succ_eph_gets = xenstat_tmem_succ_eph_gets(tmem);
	unsigned long long succ_pers_puts = xenstat_tmem_succ_pers_puts(tmem);
	unsigned long long succ_pers_gets = xenstat_tmem_succ_pers_gets(tmem);

	if (curr_eph_pages | succ_eph_gets | succ_pers_puts | succ_pers_gets)
		print("Tmem:  Curr eph pages: %8llu   Succ eph gets: %8llu   "
	              "Succ pers puts: %8llu   Succ pers gets: %8llu\n",
			curr_eph_pages, succ_eph_gets,
			succ_pers_puts, succ_pers_gets);

}

static void top(void)
{
	xenstat_domain **domains;
	unsigned int i, num_domains = 0;

	/* Now get the node information */
	if (prev_node != NULL)
		xenstat_free_node(prev_node);
	prev_node = cur_node;
	cur_node = xenstat_get_node(xhandle, XENSTAT_ALL);
	if (cur_node == NULL)
		fail("Failed to retrieve statistics from libxenstat\n");

	/* dump summary top information */
	if (!batch)
		do_summary();

	/* Count the number of domains for which to report data */
	num_domains = xenstat_node_num_domains(cur_node);

	domains = calloc(num_domains, sizeof(xenstat_domain *));
	if(domains == NULL)
		fail("Failed to allocate memory\n");

	for (i=0; i < num_domains; i++)
		domains[i] = xenstat_node_domain_by_index(cur_node, i);

	/* Sort */
	qsort(domains, num_domains, sizeof(xenstat_domain *),
	      (int(*)(const void *, const void *))compare_domains);

	if(first_domain_index >= num_domains)
		first_domain_index = num_domains-1;

	/* Adjust default_width for fields with potentially large numbers */
	reset_field_widths();
	for (i = first_domain_index; i < num_domains; i++) {
		adjust_field_widths(domains[i]);
	}

	for (i = first_domain_index; i < num_domains; i++) {
		if(!batch && current_row() == lines()-1)
			break;
		if (i == first_domain_index || repeat_header)
			do_header();
		do_domain(domains[i]);
		if (show_vcpus)
			do_vcpu(domains[i]);
		if (show_networks)
			do_network(domains[i]);
		if (show_vbds)
			do_vbd(domains[i]);
		if (show_tmem)
			do_tmem(domains[i]);
	}

	if (!batch)
		do_bottom_line();

	free(domains);
}

static int signal_exit;

static void signal_exit_handler(int sig)
{
	signal_exit = 1;
}

int main(int argc, char **argv)
{
	int opt, optind = 0;
	int ch = ERR;

	struct option lopts[] = {
		{ "help",          no_argument,       NULL, 'h' },
		{ "version",       no_argument,       NULL, 'V' },
		{ "networks",      no_argument,       NULL, 'n' },
		{ "vbds",          no_argument,       NULL, 'x' },
		{ "repeat-header", no_argument,       NULL, 'r' },
		{ "vcpus",         no_argument,       NULL, 'v' },
		{ "delay",         required_argument, NULL, 'd' },
		{ "batch",	   no_argument,	      NULL, 'b' },
		{ "iterations",	   required_argument, NULL, 'i' },
		{ "full-name",     no_argument,       NULL, 'f' },
		{ 0, 0, 0, 0 },
	};
	const char *sopts = "hVnxrvd:bi:f";

	if (atexit(cleanup) != 0)
		fail("Failed to install cleanup handler.\n");

	while ((opt = getopt_long(argc, argv, sopts, lopts, &optind)) != -1) {
		switch (opt) {
		default:
			usage(argv[0]);
			exit(1);
		case '?':
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			version();
			exit(0);
		case 'n':
			show_networks = 1;
			break;
		case 'x':
			show_vbds = 1;
			break;
		case 'r':
			repeat_header = 1;
			break;
		case 'v':
			show_vcpus = 1;
			break;
		case 'd':
			delay = atoi(optarg);
			break;
		case 'b':
			batch = 1;
			break;
		case 'i':
			iterations = atoi(optarg);
			loop = 0;
			break;
		case 'f':
			show_full_name = 1;
			break;
		case 't':
			show_tmem = 1;
			break;
		}
	}

	/* Get xenstat handle */
	xhandle = xenstat_init();
	if (xhandle == NULL)
		fail("Failed to initialize xenstat library\n");

	if (!batch) {
		/* Begin curses stuff */
		cwin = initscr();
		start_color();
		cbreak();
		noecho();
		nonl();
		keypad(stdscr, TRUE);
		halfdelay(5);
#ifndef __sun__
		use_default_colors();
#endif
		init_pair(1, -1, COLOR_YELLOW);

		do {
			gettimeofday(&curtime, NULL);
			if(ch != ERR || (curtime.tv_sec - oldtime.tv_sec) >= delay) {
				erase();
				top();
				oldtime = curtime;
				refresh();
				if ((!loop) && !(--iterations))
					break;
			}
			ch = getch();
		} while (handle_key(ch));
	} else {
		struct sigaction sa = {
			.sa_handler = signal_exit_handler,
			.sa_flags = 0
		};
		sigemptyset(&sa.sa_mask);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);

		do {
			gettimeofday(&curtime, NULL);
			top();
			fflush(stdout);
			oldtime = curtime;
			if ((!loop) && !(--iterations))
				break;
			sleep(delay);
		} while (!signal_exit);
	}

	/* Cleanup occurs in cleanup(), so no work to do here. */

	return 0;
}
