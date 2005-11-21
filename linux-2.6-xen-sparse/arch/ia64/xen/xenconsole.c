#include <linux/config.h>
#include <linux/console.h>

int
early_xen_console_setup (char *cmdline)
{
#ifdef CONFIG_XEN
#ifndef CONFIG_IA64_HP_SIM
	extern int running_on_xen;
	if (running_on_xen) {
		extern struct console hpsim_cons;
		hpsim_cons.flags |= CON_BOOT;
		register_console(&hpsim_cons);
		return 0;
	}
#endif
#endif
	return -1;
}
