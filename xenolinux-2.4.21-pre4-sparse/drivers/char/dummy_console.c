// This file is unashamed hackery to allow keyboard support without console/vt support.  
// It could be made more useful by linking sysrq in somehow..
// But right now its just for testing keyboard functionality in Xen while console functionality is not yet implemented.

#include <linux/config.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/init.h>

#include <asm/keyboard.h>
#include <asm/bitops.h>

#include <linux/kbd_kern.h>
#include <linux/kbd_diacr.h>
#include <linux/vt_kern.h>
#include <linux/kbd_ll.h>
#include <linux/sysrq.h>
#include <linux/pm.h>


static void kbd_bh(unsigned long dummy)
{
}

EXPORT_SYMBOL(keyboard_tasklet);
DECLARE_TASKLET_DISABLED(keyboard_tasklet, kbd_bh, 0);

int (*kbd_rate)(struct kbd_repeat *rep);

int __init kbd_init(void) {
  kbd_init_hw();
}
