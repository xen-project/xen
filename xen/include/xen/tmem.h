/******************************************************************************
 * tmem.h
 *
 * Transcendent memory
 *
 * Copyright (c) 2008, Dan Magenheimer, Oracle Corp.
 */

#ifndef __XEN_TMEM_H__
#define __XEN_TMEM_H__

struct xen_sysctl_tmem_op;

extern int tmem_control(struct xen_sysctl_tmem_op *op);
extern void tmem_destroy(void *);
extern void *tmem_relinquish_pages(unsigned int, unsigned int);
extern unsigned long tmem_freeable_pages(void);

#endif /* __XEN_TMEM_H__ */
