#ifndef _LINUX_REBOOT_H
#define _LINUX_REBOOT_H

extern void machine_restart(char *cmd);
extern void machine_halt(void);
extern void machine_power_off(void);

#endif /* _LINUX_REBOOT_H */
