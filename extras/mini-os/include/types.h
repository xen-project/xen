/* -*-  Mode:C; c-basic-offset:4; tab-width:4 -*-
 ****************************************************************************
 * (C) 2003 - Rolf Neugebauer - Intel Research Cambridge
 ****************************************************************************
 *
 *        File: types.h
 *      Author: Rolf Neugebauer (neugebar@dcs.gla.ac.uk)
 *     Changes: 
 *              
 *        Date: May 2003
 * 
 * Environment: Xen Minimal OS
 * Description: a random collection of type definitions
 *
 ****************************************************************************
 * $Id: h-insert.h,v 1.4 2002/11/08 16:03:55 rn Exp $
 ****************************************************************************
 */

#ifndef _TYPES_H_
#define _TYPES_H_

typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
#ifdef __i386__
typedef signed long long    s64;
typedef unsigned long long  u64;
#elif defined(__x86_64__)
typedef signed long         s64;
typedef unsigned long       u64;
#endif

typedef unsigned int        size_t;

/* FreeBSD compat types */
typedef unsigned char       u_char;
typedef unsigned int        u_int;
typedef unsigned long       u_long;
#ifdef __i386__
typedef long long           quad_t;
typedef unsigned long long  u_quad_t;
typedef unsigned int        uintptr_t;
#elif defined(__x86_64__)
typedef long                quad_t;
typedef unsigned long       u_quad_t;
typedef unsigned long       uintptr_t;
#endif
#endif /* _TYPES_H_ */
