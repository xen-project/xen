/******************************************************************************
 * x86_emulate.c
 * 
 * Wrapper for generic x86 instruction decoder and emulator.
 * 
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <asm/x86_emulate.h>

/* Avoid namespace pollution. */
#undef cmpxchg

#include "x86_emulate/x86_emulate.c"
