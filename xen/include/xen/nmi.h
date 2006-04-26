/******************************************************************************
 * nmi.h
 *
 * Register and unregister NMI callbacks.
 *
 * Copyright (c) 2006, Ian Campbell <ian.campbell@xensource.com>
 */

#ifndef __XEN_NMI_H__
#define __XEN_NMI_H__

#include <asm/nmi.h>

/**
 * register_guest_nmi_callback
 *
 * The default NMI handler passes the NMI to a guest callback. This
 * function registers the address of that callback.
 */
extern long register_guest_nmi_callback(unsigned long address);

/**
 * unregister_guest_nmi_callback
 *
 * Unregister a guest NMI handler.
 */
extern long unregister_guest_nmi_callback(void);

#endif /* __XEN_NMI_H__ */
