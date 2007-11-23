/* 
 * Done by Dietmar Hahn <dietmar.hahn@fujitsu-siemens.com>
 * Description: simple ia64 specific time handling
 * mktime() is taken from Linux (see copyright below)
 * Parts are taken from FreeBSD.
 *
 ****************************************************************************
 * For the copy of the mktime() from linux.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 ****************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "os.h"
#include "console.h"
#include "time.h"
#include "efi.h"
#include "events.h"

struct timespec os_time;
static uint64_t itc_alt;		/* itc on last update. */
static uint64_t itc_at_boot;		/* itc on boot */
static uint64_t itc_frequency;
static uint64_t processor_frequency;
static uint64_t itm_val;


/*
 * mktime() is take from Linux. See copyright above.
 * Converts Gregorian date to seconds since 1970-01-01 00:00:00.
 * Assumes input in normal date format, i.e. 1980-12-31 23:59:59
 * => year=1980, mon=12, day=31, hour=23, min=59, sec=59.
 *
 * [For the Julian calendar (which was used in Russia before 1917,
 * Britain & colonies before 1752, anywhere else before 1582,
 * and is still in use by some communities) leave out the
 * -year/100+year/400 terms, and add 10.]
 *
 * This algorithm was first published by Gauss (I think).
 *
 * WARNING: this function will overflow on 2106-02-07 06:28:16 on
 * machines were long is 32-bit! (However, as time_t is signed, we
 * will already get problems at other places on 2038-01-19 03:14:08)
 */
static unsigned long
mktime(const unsigned int year0, const unsigned int mon0,
       const unsigned int day, const unsigned int hour,
       const unsigned int min, const unsigned int sec)
{
	unsigned int mon = mon0, year = year0;

	/* 1..12 -> 11,12,1..10 */
	if (0 >= (int) (mon -= 2)) {
		mon += 12;	/* Puts Feb last since it has leap day */
		year -= 1;
	}

	return (
		(
		 ((unsigned long)
		  (year/4 - year/100 + year/400 + 367*mon/12 + day) +
		   year*365 - 719499
		 ) * 24 + hour /* now have hours */
		) * 60 + min /* now have minutes */
	       ) * 60 + sec; /* finally seconds */
}

static inline uint64_t
ns_from_cycles(uint64_t cycles)
{
	return (cycles * (1000000000 / itc_frequency));
}

static inline uint64_t
ns_to_cycles(uint64_t ns)
{
	return (ns * (itc_frequency / 1000000000));
}

/*
 * Block the domain until until(nanoseconds) is over.
 * If block is called no timerinterrupts are delivered from xen!
 */
void
block_domain(s_time_t until)
{
	struct ia64_pal_result pal_res;
	uint64_t c, new;

	c = ns_to_cycles(until);
	new = ia64_get_itc() + c - NOW();
	ia64_set_itm(new);		/* Reload cr.itm */
	/*
	 * PAL_HALT_LIGHT returns on every external interrupt,
	 * including timer interrupts.
	 */
	pal_res = ia64_call_pal_static(PAL_HALT_LIGHT, 0, 0, 0);
	if (pal_res.pal_status != 0)
		printk("%s: PAL_HALT_LIGHT returns an error\n");
	/* Reload the normal timer interrupt match. */
	new = ia64_get_itc() + itm_val;
	ia64_set_itm(new);
}

static void
calculate_time(void)
{
	uint64_t itc_new, new;

	itc_new = ia64_get_itc();
	if (itc_new < itc_alt)
		new = ~0 - itc_alt + itc_new;
	else
		new = itc_new - itc_alt;
	itc_alt = itc_new;
	new = ns_from_cycles(new);
	os_time.ts_nsec += new;
	if (os_time.ts_nsec > 1000000000) {	/* On overflow. */
		os_time.ts_sec++;
		os_time.ts_nsec -= 1000000000;
	}
}

void
timer_interrupt(evtchn_port_t port, struct pt_regs* regsP, void *data)
{
	uint64_t new;

	calculate_time();
	new = ia64_get_itc() + itm_val;
	ia64_set_itm(new);
}

/*
 * monotonic_clock(): returns # of nanoseconds passed since time_init()
 */
u64
monotonic_clock(void)
{
	uint64_t delta;

	delta = ia64_get_itc() - itc_at_boot;
	delta = ns_from_cycles(delta);
	return delta;
}

void
gettimeofday(struct timeval *tv)
{
	calculate_time();
	tv->tv_sec = os_time.ts_sec;			/* seconds */
	tv->tv_usec = NSEC_TO_USEC(os_time.ts_nsec);	/* microseconds */
};

/*
 * Read the clock frequencies from pal and sal for calculating
 * the clock interrupt.
 */
static void
calculate_frequencies(void)
{
	struct ia64_sal_result sal_res;
	struct ia64_pal_result pal_res;

	pal_res = ia64_call_pal_static(PAL_FREQ_RATIOS, 0, 0, 0);
	//sal_res = ia64_sal_call(SAL_FREQ_BASE, 0, 0, 0, 0, 0, 0, 0);
#if defined(BIG_ENDIAN)
//#warning calculate_frequencies TODO
	/*
	 * I have to do an own function with switching psr.be!
	 * Currently it's running because it's a break into the hypervisor
	 * behind the call.!
	 */
#endif
	sal_res = ia64_sal_entry(SAL_FREQ_BASE, 0, 0, 0, 0, 0, 0, 0);

	if (sal_res.sal_status == 0 && pal_res.pal_status == 0) {
		processor_frequency =
			sal_res.sal_result[0] * (pal_res.pal_result[0] >> 32)
				/ (pal_res.pal_result[0] & ((1L << 32) - 1));
		itc_frequency =
			sal_res.sal_result[0] * (pal_res.pal_result[2] >> 32)
				/ (pal_res.pal_result[2] & ((1L << 32) - 1));
		PRINT_BV("Reading clock frequencies:\n");
		PRINT_BV("  Platform clock frequency %ld Hz\n",
			       sal_res.sal_result[0]);
		PRINT_BV("  Processor ratio %ld/%ld, Bus ratio %ld/%ld, "
			       "  ITC ratio %ld/%ld\n",
			       pal_res.pal_result[0] >> 32,
			       pal_res.pal_result[0] & ((1L << 32) - 1),
			       pal_res.pal_result[1] >> 32,
			       pal_res.pal_result[1] & ((1L << 32) - 1),
			       pal_res.pal_result[2] >> 32,
			       pal_res.pal_result[2] & ((1L << 32) - 1));

		printk("  ITC frequency %ld\n", itc_frequency);
	} else {
		itc_frequency = 1000000000;
		processor_frequency = 0;
		printk("Reading clock frequencies failed!!! Using: %ld\n",
		       itc_frequency);
	}
}


//#define HZ 1
#define HZ 1000		// 1000 clock ticks per sec
#define IA64_TIMER_VECTOR 0xef

void
init_time(void)
{
	uint64_t new;
	efi_time_t tm;
	int err = 0;

	printk("Initialising time\n");
	calculate_frequencies();

	itm_val = (itc_frequency + HZ/2) / HZ;
	printk("  itm_val: %ld\n", itm_val);

	os_time.ts_sec = 0;
	os_time.ts_nsec = 0;

	if (efi_get_time(&tm)) {
		printk("  EFI-Time: %d.%d.%d   %d:%d:%d\n", tm.Day,
		       tm.Month, tm.Year, tm.Hour, tm.Minute, tm.Second);
		os_time.ts_sec = mktime(SWAP(tm.Year), SWAP(tm.Month),
					SWAP(tm.Day), SWAP(tm.Hour),
					SWAP(tm.Minute), SWAP(tm.Second));
		os_time.ts_nsec = tm.Nanosecond;
	} else
		printk("efi_get_time() failed\n");

	err = bind_virq(VIRQ_ITC, timer_interrupt, NULL);
	if (err == -1) {
		printk("XEN timer request chn bind failed %i\n", err);
		return;
	}
	itc_alt = ia64_get_itc();
	itc_at_boot = itc_alt;
	new = ia64_get_itc() + itm_val;
	ia64_set_itv(IA64_TIMER_VECTOR);
	ia64_set_itm(new);
	ia64_srlz_d();
}
