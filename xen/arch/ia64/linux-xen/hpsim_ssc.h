/*
 * Platform dependent support for HP simulator.
 *
 * Copyright (C) 1998, 1999 Hewlett-Packard Co
 * Copyright (C) 1998, 1999 David Mosberger-Tang <davidm@hpl.hp.com>
 * Copyright (C) 1999 Vijay Chander <vijay@engr.sgi.com>
 */
#ifndef _IA64_PLATFORM_HPSIM_SSC_H
#define _IA64_PLATFORM_HPSIM_SSC_H

/* Simulator system calls: */

#define SSC_CONSOLE_INIT		20
#define SSC_GETCHAR			21
#define SSC_PUTCHAR			31
#define SSC_CONNECT_INTERRUPT		58
#define SSC_GENERATE_INTERRUPT		59
#define SSC_SET_PERIODIC_INTERRUPT	60
#define SSC_GET_RTC			65
#define SSC_EXIT			66
#define SSC_LOAD_SYMBOLS		69
#define SSC_GET_TOD			74
#define SSC_CTL_TRACE			76

#define SSC_NETDEV_PROBE		100
#define SSC_NETDEV_SEND			101
#define SSC_NETDEV_RECV			102
#define SSC_NETDEV_ATTACH		103
#define SSC_NETDEV_DETACH		104

/*
 * Simulator system call.
 */
extern long ia64_ssc (long arg0, long arg1, long arg2, long arg3, int nr);

#ifdef XEN
/* Note: These are declared in linux/arch/ia64/hp/sim/simscsi.c but belong
 * in linux/include/asm-ia64/hpsim_ssc.h, hence their addition here */
#define SSC_OPEN			50
#define SSC_CLOSE			51
#define SSC_READ			52
#define SSC_WRITE			53
#define SSC_GET_COMPLETION		54
#define SSC_WAIT_COMPLETION		55

#define SSC_WRITE_ACCESS		2
#define SSC_READ_ACCESS			1

struct ssc_disk_req {
	unsigned long addr;
	unsigned long len;
};
#endif

#endif /* _IA64_PLATFORM_HPSIM_SSC_H */
