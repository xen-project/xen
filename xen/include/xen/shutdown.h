#ifndef __XEN_SHUTDOWN_H__
#define __XEN_SHUTDOWN_H__

#include <xen/compiler.h>
#include <xen/types.h>

/* opt_noreboot: If true, machine will need manual reset on error. */
extern bool opt_noreboot;

void noreturn hwdom_shutdown(unsigned char reason);

void noreturn machine_restart(unsigned int delay_millisecs);
void noreturn machine_halt(void);

#endif /* __XEN_SHUTDOWN_H__ */
