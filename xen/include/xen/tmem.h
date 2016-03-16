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

#ifdef CONFIG_TMEM
extern int tmem_control(struct xen_sysctl_tmem_op *op);
extern void tmem_destroy(void *);
extern void *tmem_relinquish_pages(unsigned int, unsigned int);
extern unsigned long tmem_freeable_pages(void);
#else
static inline int
tmem_control(struct xen_sysctl_tmem_op *op)
{
    return -ENOSYS;
}

static inline void
tmem_destroy(void *p)
{
    return;
}

static inline void *
tmem_relinquish_pages(unsigned int x, unsigned int y)
{
    return NULL;
}

static inline unsigned long
tmem_freeable_pages(void)
{
    return 0;
}
#endif /* CONFIG_TMEM */

#endif /* __XEN_TMEM_H__ */
