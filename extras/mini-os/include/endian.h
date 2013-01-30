#ifndef	_ENDIAN_H_
#define	_ENDIAN_H_

#define	__LITTLE_ENDIAN	1234
#define	__BIG_ENDIAN	4321
#define	__PDP_ENDIAN	3412

#define ARCH_ENDIAN_H
/* This will define __BYTE_ORDER for the current arch */
#include <arch_endian.h>
#undef ARCH_ENDIAN_H

#include <arch_wordsize.h>

#define BYTE_ORDER __BYTE_ORDER
#define BIG_ENDIAN __BIG_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN

#endif	/* endian.h */
