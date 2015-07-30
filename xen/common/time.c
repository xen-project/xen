/******************************************************************************
 * time.c
 * 
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/time.h>

/* Nonzero if YEAR is a leap year (every 4 years,
   except every 100th isn't, and every 400th is).  */
#define __isleap(year) \
  ((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))

/* How many days are in each month.  */
const unsigned short int __mon_lengths[2][12] = {
    /* Normal years.  */
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    /* Leap years.  */
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
};

#define SECS_PER_HOUR (60 * 60)
#define SECS_PER_DAY  (SECS_PER_HOUR * 24)

struct tm gmtime(unsigned long t)
{
    struct tm tbuf;
    long days, rem;
    int y;
    const unsigned short int *ip;

    y = 1970;
#if BITS_PER_LONG >= 64
    /* Allow the concept of time before 1970.  64-bit only; for 32-bit
     * time after 2038 seems more important than time before 1970. */
    while ( t & (1UL<<39) )
    {
        y -= 400;
        t += ((unsigned long)(365 * 303 + 366 * 97)) * SECS_PER_DAY;
    }
    t &= (1UL << 40) - 1;
#endif

    days = t / SECS_PER_DAY;
    rem = t % SECS_PER_DAY;

    tbuf.tm_hour = rem / SECS_PER_HOUR;
    rem %= SECS_PER_HOUR;
    tbuf.tm_min = rem / 60;
    tbuf.tm_sec = rem % 60;
    /* January 1, 1970 was a Thursday.  */
    tbuf.tm_wday = (4 + days) % 7;
    if ( tbuf.tm_wday < 0 )
        tbuf.tm_wday += 7;
    while ( days >= (rem = __isleap(y) ? 366 : 365) )
    {
        ++y;
        days -= rem;
    }
    while ( days < 0 )
    {
        --y;
        days += __isleap(y) ? 366 : 365;
    }
    tbuf.tm_year = y - 1900;
    tbuf.tm_yday = days;
    ip = (const unsigned short int *)__mon_lengths[__isleap(y)];
    for ( y = 0; days >= ip[y]; ++y )
        days -= ip[y];
    tbuf.tm_mon = y;
    tbuf.tm_mday = days + 1;
    tbuf.tm_isdst = -1;

    return tbuf;
}
