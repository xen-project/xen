/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2002 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: time.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: Nov 2002
 * 
 * Environment: Xen Hypervisor
 * Description: Architecture dependent definition of time variables
 *
 ****************************************************************************
 * $Id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn Exp $
 ****************************************************************************
 */

#ifndef _ASM_TIME_H_
#define _ASM_TIME_H_

#include <asm/types.h>
#include <asm/msr.h>

/*
 * Cycle Counter Time
 */
typedef u64 cc_time_t;
static inline cc_time_t get_cc_time()
{
	u64 ret;
	rdtscll(ret);
	return ret;
}

/*
 * System Time
 */
typedef s64      s_time_t;	     /* System time */
extern  u32      stime_pcc;      /* cycle counter value at last timer irq */
extern  s_time_t stime_now;      /* time in ns at last timer IRQ */

/*
 * Domain Virtual Time
 */
typedef u64 dv_time_t;

extern int using_apic_timer;

#endif /* _ASM_TIME_H_ */
