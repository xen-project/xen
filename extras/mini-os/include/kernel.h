#ifndef _KERNEL_H_
#define _KERNEL_H_

extern unsigned int do_shutdown;
extern unsigned int shutdown_reason;
extern struct wait_queue_head shutdown_queue;
extern void do_exit(void) __attribute__((noreturn));
extern void stop_kernel(void);

#endif /* _KERNEL_H_ */
