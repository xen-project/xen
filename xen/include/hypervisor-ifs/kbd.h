/******************************************************************************
 * kbd.h
 *
 * PS/2 interface definitions
 * Copyright (c) 2003 James Scott, Intel Research Cambridge
 */

#ifndef __HYPERVISOR_KBD_H__
#define __HYPERVISOR_KBD_H__

			 
#define KBD_OP_WRITEOUTPUT   0
#define KBD_OP_WRITECOMMAND  1
#define KBD_OP_READ          2

#define KBD_CODE_SCANCODE(_r) ((unsigned char)((_r) & 0xff))
#define KBD_CODE_STATUS(_r) ((unsigned char)(((_r) >> 8) & 0xff))
#define KBD_CODE(_c, _s) ((int)(((_c) & 0xff)  | (((_s) & 0xff) << 8)))

#endif
