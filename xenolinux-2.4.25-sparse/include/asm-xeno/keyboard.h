/* xenolinux/include/asm-xeno/keyboard.h */
/* Portions copyright (c) 2003 James Scott, Intel Research Cambridge */
/*
 * Talks to hypervisor to get PS/2 keyboard and mouse events, and send keyboard
 * and mouse commands
 */

/*  Based on:
 *  linux/include/asm-i386/keyboard.h
 *
 *  Created 3 Nov 1996 by Geert Uytterhoeven
 */

#ifndef _XENO_KEYBOARD_H
#define _XENO_KEYBOARD_H

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/ioport.h>
#include <linux/kd.h>
#include <linux/pm.h>
#include <asm/io.h>

extern int pckbd_setkeycode(unsigned int scancode, unsigned int keycode);
extern int pckbd_getkeycode(unsigned int scancode);
extern int pckbd_translate(unsigned char scancode, unsigned char *keycode,
			   char raw_mode);
extern char pckbd_unexpected_up(unsigned char keycode);
extern void pckbd_leds(unsigned char leds);
extern void pckbd_init_hw(void);
extern int pckbd_pm_resume(struct pm_dev *, pm_request_t, void *);

extern pm_callback pm_kbd_request_override;
extern unsigned char pckbd_sysrq_xlate[128];

#define kbd_setkeycode		pckbd_setkeycode
#define kbd_getkeycode		pckbd_getkeycode
#define kbd_translate		pckbd_translate
#define kbd_unexpected_up	pckbd_unexpected_up
#define kbd_leds		pckbd_leds
#define kbd_init_hw		pckbd_init_hw
#define kbd_sysrq_xlate		pckbd_sysrq_xlate

#define SYSRQ_KEY 0x54


/* THIS SECTION TALKS TO XEN TO DO PS2 SUPPORT */
#include <asm/hypervisor-ifs/kbd.h>
#include <asm/hypervisor-ifs/hypervisor-if.h>

#define kbd_controller_present xen_kbd_controller_present

static inline int xen_kbd_controller_present ()
{
    return start_info.flags & SIF_INITDOMAIN;
}

/* resource allocation */
#define kbd_request_region()     \
    do { } while (0)
#define kbd_request_irq(handler) \
    request_irq(HYPEREVENT_IRQ(_EVENT_PS2), handler, 0, "ps/2", NULL)

/* could implement these with command to xen to filter mouse stuff... */
#define aux_request_irq(hand, dev_id) 0
#define aux_free_irq(dev_id) do { } while(0)

/* Some stoneage hardware needs delays after some operations.  */
#define kbd_pause() do { } while(0)

static unsigned char kbd_current_scancode = 0;

static unsigned char kbd_read_input(void) 
{
  return kbd_current_scancode;
}

static unsigned char kbd_read_status(void) 
{
  long res;
  res = HYPERVISOR_kbd_op(KBD_OP_READ,0);
  if ( res<0 ) 
  {
    kbd_current_scancode = 0;
    return 0; /* error with our request - wrong domain? */
  }
  kbd_current_scancode = KBD_CODE_SCANCODE(res);
  return KBD_CODE_STATUS(res);
}


#define kbd_write_output(val)  HYPERVISOR_kbd_op(KBD_OP_WRITEOUTPUT, val);
#define kbd_write_command(val) HYPERVISOR_kbd_op(KBD_OP_WRITECOMMAND, val);


#endif /* __KERNEL__ */
#endif /* _XENO_KEYBOARD_H */
