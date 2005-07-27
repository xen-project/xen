/******************************************************************************
 * event.h
 *
 * A nice interface for passing asynchronous events to guest OSes.
 * (architecture-dependent part)
 *
 */

#ifndef __ASM_EVENT_H__
#define __ASM_EVENT_H__

#include <asm/vcpu.h>

static inline void evtchn_notify(struct vcpu *v)
{
	vcpu_pend_interrupt(v, VCPU(v,evtchn_vector));
}

#endif
