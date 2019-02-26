#ifndef __XEN_PV_CONSOLE_H__
#define __XEN_PV_CONSOLE_H__

#include <xen/serial.h>

#ifdef CONFIG_XEN_GUEST

void pv_console_init(void);
void pv_console_set_rx_handler(serial_rx_fn fn);
void pv_console_init_postirq(void);
void pv_console_puts(const char *buf, size_t nr);
size_t pv_console_rx(struct cpu_user_regs *regs);
evtchn_port_t pv_console_evtchn(void);

#else

static inline void pv_console_init(void) {}
static inline void pv_console_set_rx_handler(serial_rx_fn fn) { }
static inline void pv_console_init_postirq(void) { }
static inline void pv_console_puts(const char *buf, size_t nr) { }
static inline size_t pv_console_rx(struct cpu_user_regs *regs) { return 0; }
evtchn_port_t pv_console_evtchn(void)
{
    ASSERT_UNREACHABLE();
    return 0;
}

#endif /* !CONFIG_XEN_GUEST */
#endif /* __XEN_PV_CONSOLE_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
