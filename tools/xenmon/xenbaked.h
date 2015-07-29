/******************************************************************************
 * TOOLS/xenbaked.h
 *
 * Header file for xenbaked
 *
 * Copyright (C) 2005 by Hewlett Packard, Palo Alto and Fort Collins
 *
 * Authors: Diwaker Gupta, diwaker.gupta@hp.com
 *          Rob Gardner, rob.gardner@hp.com
 *          Lucy Cherkasova, lucy.cherkasova.hp.com
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

#ifndef __QOS_H__
#define __QOS_H__

///// qos stuff
#define million 1000000LL
#define billion 1000000000LL

// caution: don't use QOS_ADD with negative numbers!
#define QOS_ADD(N,A) ((N+A)<(NSAMPLES-1) ? (N+A) : A)
#define QOS_INCR(N) ((N<(NSAMPLES-2)) ? (N+1) : 0)
#define QOS_DECR(N) ((N==0) ? (NSAMPLES-1) : (N-1))

#define MAX_NAME_SIZE 32
#define IDLE_DOMAIN_ID 32767

/* Number of domains we can keep track of in memory */
#define NDOMAINS 32

/* Number of data points to keep */
#define NSAMPLES 100

#define ID(X) ((X>NDOMAINS-1)?(NDOMAINS-1):X)
#define DEFAULT_TBUF_SIZE 20

// per domain stuff
typedef struct 
{
  uint64_t last_update_time;
  uint64_t start_time;		// when the thread started running
  uint64_t runnable_start_time;	// when the thread became runnable
  uint64_t blocked_start_time;	// when the thread became blocked
  uint64_t ns_since_boot;		// time gone by since boot
  uint64_t ns_oncpu_since_boot;	// total cpu time used by thread since boot
  //  uint64_t ns_runnable_since_boot;
  int runnable_at_last_update; // true if the thread was runnable last time we checked.
  int runnable;			// true if thread is runnable right now
  // tells us something about what happened during the 
  // sample period that we are analysing right now
  int in_use;			// 
  domid_t  id;
  char     name[MAX_NAME_SIZE];
} _domain_info;



typedef struct 
{
  struct 
  {
// data point:
//   stuff that is recorded once for each measurement interval
    uint64_t ns_gotten[NDOMAINS];		// ns used in the last sample period
    uint64_t ns_allocated[NDOMAINS];		// ns allocated by scheduler
    uint64_t ns_waiting[NDOMAINS];		// ns spent waiting to execute, ie, time from
                                        // becoming runnable until actually running
    uint64_t ns_blocked[NDOMAINS];		// ns spent blocked
    uint64_t switchin_count[NDOMAINS]; // number of executions of the domain	
    uint64_t io_count[NDOMAINS];
    uint64_t ns_passed;              // ns gone by on the wall clock, ie, the sample period
    uint64_t timestamp;
    uint64_t lost_records;		// # of lost trace records this time period
    uint64_t flip_free_periods;	// # of executions of dom0 in which no page flips happened
  } qdata[NSAMPLES];
  
  _domain_info domain_info[NDOMAINS];
  
  // control information
  int next_datapoint;
  int ncpu;
  int structlen;

  // parameters
  int measurement_frequency;	// for example
  
} _new_qos_data;



#endif
