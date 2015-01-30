#ifndef _KERNEL_H_
#define _KERNEL_H_

void start_kernel(void);
void do_exit(void) __attribute__((noreturn));
void arch_do_exit(void);
void stop_kernel(void);

#endif /* _KERNEL_H_ */
