#ifndef _XENCONS_RING_H
#define _XENCONS_RING_H

asmlinkage int xprintk(const char *fmt, ...);


int xencons_ring_init(void);
int xencons_ring_send(const char *data, unsigned len);

typedef void (xencons_receiver_func)(char *buf, unsigned len, 
                                     struct pt_regs *regs);
void xencons_ring_register_receiver(xencons_receiver_func *f);

#endif /* _XENCONS_RING_H */
