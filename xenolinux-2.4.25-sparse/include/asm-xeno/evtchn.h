/******************************************************************************
 * evtchn.h
 * 
 * Driver for receiving and demuxing event-channel signals.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#ifndef __ASM_EVTCHN_H__
#define __ASM_EVTCHN_H__

typedef void (*evtchn_receiver_t)(unsigned int);
#define PORT_NORMAL     0x0000
#define PORT_DISCONNECT 0x8000
#define PORTIDX_MASK    0x7fff

/* /dev/xen/evtchn resides at device number major=10, minor=200 */
#define EVTCHN_MINOR 200

/* /dev/xen/evtchn ioctls: */
/* EVTCHN_RESET: Clear and reinit the event buffer. Clear error condition. */
#define EVTCHN_RESET _IO('E', 1)

int evtchn_request_port(unsigned int port, evtchn_receiver_t rx_fn);
int evtchn_free_port(unsigned int port);
void evtchn_clear_port(unsigned int port);


#endif /* __ASM_EVTCHN_H__ */
