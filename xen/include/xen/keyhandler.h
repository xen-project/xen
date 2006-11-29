/******************************************************************************
 * keyhandler.h
 * 
 * We keep an array of 'handlers' for each key code between 0 and 255;
 * this is intended to allow very simple debugging routines (toggle 
 * debug flag, dump registers, reboot, etc) to be hooked in in a slightly
 * nicer fashion than just editing the serial/keyboard drivers. 
 */

#ifndef __XEN_KEYHANDLER_H__
#define __XEN_KEYHANDLER_H__

/* Initialize keytable with default handlers */
extern void initialize_keytable(void);

/*
 * Register a callback function for key @key. The callback occurs in
 * softirq context with no locks held and interrupts enabled.
 */
typedef void keyhandler_t(unsigned char key);
extern void register_keyhandler(
    unsigned char key, keyhandler_t *handler, char *desc);

/*
 * Register an IRQ callback function for key @key. The callback occurs
 * synchronously in hard-IRQ context with interrupts disabled. The @regs
 * callback parameter points at the interrupted register context.
 */
typedef void irq_keyhandler_t(unsigned char key, struct cpu_user_regs *regs);
extern void register_irq_keyhandler(
    unsigned char key, irq_keyhandler_t *handler, char *desc);

/* Inject a keypress into the key-handling subsystem. */
extern void handle_keypress(unsigned char key, struct cpu_user_regs *regs);

#endif /* __XEN_KEYHANDLER_H__ */
