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

#include <xen/types.h>

/*
 * Callback type for keyhander.
 *
 * Called in softirq context with interrupts enabled.
 */
typedef void (keyhandler_fn_t)(unsigned char key);

/*
 * Callback type for irq_keyhandler.
 *
 * Called in hardirq context with interrupts disabled.
 */
struct cpu_user_regs;
typedef void (irq_keyhandler_fn_t)(unsigned char key,
                                   struct cpu_user_regs *regs);

/* Initialize keytable with default handlers. */
void initialize_keytable(void);

/*
 * Regiser a callback handler for key @key for either plain or irq context.
 * If @diagnostic is set, the handler will be included in the "dump
 * everything" keyhandler.
 */
void register_keyhandler(unsigned char key,
                         keyhandler_fn_t *fn,
                         const char *desc,
                         bool_t diagnostic);
void register_irq_keyhandler(unsigned char key,
                             irq_keyhandler_fn_t *fn,
                             const char *desc,
                             bool_t diagnostic);

/* Inject a keypress into the key-handling subsystem. */
extern void handle_keypress(unsigned char key, struct cpu_user_regs *regs);

/* Scratch space is available for use of any keyhandler. */
extern char keyhandler_scratch[1024];

#endif /* __XEN_KEYHANDLER_H__ */
