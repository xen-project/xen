/*
 * Minimalist Kernel Debugger
 *
 * Copyright (C) 1999 Silicon Graphics, Inc.
 * Copyright (C) Scott Lurndal (slurn@engr.sgi.com)
 * Copyright (C) Scott Foehner (sfoehner@engr.sgi.com)
 * Copyright (C) Srinivasa Thirumalachar (sprasad@engr.sgi.com)
 *
 * See the file LIA-COPYRIGHT for additional information.
 *
 * Written March 1999 by Scott Lurndal at Silicon Graphics, Inc.
 *
 * Modifications from:
 *      Richard Bass                    1999/07/20
 *              Many bug fixes and enhancements.
 *      Scott Foehner
 *              Port to ia64
 *	Scott Lurndal			1999/12/12
 *		v1.0 restructuring.
 *	Keith Owens			2000/05/23
 *		KDB v1.2
 */
#if !defined(_ASM_KDBPRIVATE_H)
#define _ASM_KDBPRIVATE_H

typedef unsigned char kdb_machinst_t;

	/*
	 * KDB_MAXBPT describes the total number of breakpoints
	 * supported by this architecure.  
	 */
#define KDB_MAXBPT	16
	/*
	 * KDB_MAXHARDBPT describes the total number of hardware
	 * breakpoint registers that exist.
	 */
#define KDB_MAXHARDBPT	 4
        /*
         * Provide space for KDB_MAX_COMMANDS commands.
         */
#define KDB_MAX_COMMANDS        125

	/*
	 * Platform specific environment entries
	 */
#define KDB_PLATFORM_ENV	"IDMODE=x86", "BYTESPERWORD=4", "IDCOUNT=16"

	/*
	 * Define the direction that the stack grows
	 */
#define KDB_STACK_DIRECTION	(-1)	/* Stack grows down */

	/*
	 * Support for ia32 debug registers 
	 */
typedef struct _kdbhard_bp {
	kdb_machreg_t	bph_reg;	/* Register this breakpoint uses */

	unsigned int	bph_free:1;	/* Register available for use */
	unsigned int	bph_data:1;	/* Data Access breakpoint */

	unsigned int	bph_write:1;	/* Write Data breakpoint */
	unsigned int	bph_mode:2;	/* 0=inst, 1=write, 2=io, 3=read */
	unsigned int	bph_length:2;	/* 0=1, 1=2, 2=BAD, 3=4 (bytes) */
} kdbhard_bp_t;

extern kdbhard_bp_t	kdb_hardbreaks[/* KDB_MAXHARDBPT */];

#define IA32_BREAKPOINT_INSTRUCTION	0xcc

#define DR6_BT  0x00008000
#define DR6_BS  0x00004000
#define DR6_BD  0x00002000

#define DR6_B3  0x00000008
#define DR6_B2  0x00000004
#define DR6_B1  0x00000002
#define DR6_B0  0x00000001

#define DR7_RW_VAL(dr, drnum) \
       (((dr) >> (16 + (4 * (drnum)))) & 0x3)

#define DR7_RW_SET(dr, drnum, rw)                              \
       do {                                                    \
               (dr) &= ~(0x3 << (16 + (4 * (drnum))));         \
               (dr) |= (((rw) & 0x3) << (16 + (4 * (drnum)))); \
       } while (0)

#define DR7_RW0(dr)       DR7_RW_VAL(dr, 0)
#define DR7_RW0SET(dr,rw)  DR7_RW_SET(dr, 0, rw)
#define DR7_RW1(dr)       DR7_RW_VAL(dr, 1)
#define DR7_RW1SET(dr,rw)  DR7_RW_SET(dr, 1, rw)
#define DR7_RW2(dr)       DR7_RW_VAL(dr, 2)
#define DR7_RW2SET(dr,rw)  DR7_RW_SET(dr, 2, rw)
#define DR7_RW3(dr)       DR7_RW_VAL(dr, 3)
#define DR7_RW3SET(dr,rw)  DR7_RW_SET(dr, 3, rw)


#define DR7_LEN_VAL(dr, drnum) \
       (((dr) >> (18 + (4 * (drnum)))) & 0x3)

#define DR7_LEN_SET(dr, drnum, rw)                             \
       do {                                                    \
               (dr) &= ~(0x3 << (18 + (4 * (drnum))));         \
               (dr) |= (((rw) & 0x3) << (18 + (4 * (drnum)))); \
       } while (0)
#define DR7_LEN0(dr)        DR7_LEN_VAL(dr, 0)
#define DR7_LEN0SET(dr,len)  DR7_LEN_SET(dr, 0, len)
#define DR7_LEN1(dr)        DR7_LEN_VAL(dr, 1)
#define DR7_LEN1SET(dr,len)  DR7_LEN_SET(dr, 1, len)
#define DR7_LEN2(dr)        DR7_LEN_VAL(dr, 2)
#define DR7_LEN2SET(dr,len)  DR7_LEN_SET(dr, 2, len)
#define DR7_LEN3(dr)        DR7_LEN_VAL(dr, 3)
#define DR7_LEN3SET(dr,len)  DR7_LEN_SET(dr, 3, len)

#define DR7_G0(dr)    (((dr)>>1)&0x1)
#define DR7_G0SET(dr) ((dr) |= 0x2)
#define DR7_G0CLR(dr) ((dr) &= ~0x2)
#define DR7_G1(dr)    (((dr)>>3)&0x1)
#define DR7_G1SET(dr) ((dr) |= 0x8)
#define DR7_G1CLR(dr) ((dr) &= ~0x8)
#define DR7_G2(dr)    (((dr)>>5)&0x1)
#define DR7_G2SET(dr) ((dr) |= 0x20)
#define DR7_G2CLR(dr) ((dr) &= ~0x20)
#define DR7_G3(dr)    (((dr)>>7)&0x1)
#define DR7_G3SET(dr) ((dr) |= 0x80)
#define DR7_G3CLR(dr) ((dr) &= ~0x80)

#define DR7_L0(dr)    (((dr))&0x1)
#define DR7_L0SET(dr) ((dr) |= 0x1)
#define DR7_L0CLR(dr) ((dr) &= ~0x1)
#define DR7_L1(dr)    (((dr)>>2)&0x1)
#define DR7_L1SET(dr) ((dr) |= 0x4)
#define DR7_L1CLR(dr) ((dr) &= ~0x4)
#define DR7_L2(dr)    (((dr)>>4)&0x1)
#define DR7_L2SET(dr) ((dr) |= 0x10)
#define DR7_L2CLR(dr) ((dr) &= ~0x10)
#define DR7_L3(dr)    (((dr)>>6)&0x1)
#define DR7_L3SET(dr) ((dr) |= 0x40)
#define DR7_L3CLR(dr) ((dr) &= ~0x40)

#define DR7_GD          0x00002000              /* General Detect Enable */
#define DR7_GE          0x00000200              /* Global exact */
#define DR7_LE          0x00000100              /* Local exact */

extern kdb_machreg_t kdba_getdr6(void);
extern void kdba_putdr6(kdb_machreg_t);

extern kdb_machreg_t kdba_getdr7(void);

extern kdb_machreg_t kdba_getdr(int);
extern void kdba_putdr(int, kdb_machreg_t);

extern kdb_machreg_t kdb_getcr(int);

#define KDB_HAVE_LONGJMP
#ifdef KDB_HAVE_LONGJMP
/*
 * Support for setjmp/longjmp
 */
#define JB_BX   0
#define JB_SI   1
#define JB_DI   2
#define JB_BP   3
#define JB_SP   4
#define JB_PC   5

typedef struct __kdb_jmp_buf {
        unsigned long   regs[6];	/* kdba_setjmp assumes fixed offsets here */
} kdb_jmp_buf;

extern int kdba_setjmp(kdb_jmp_buf *);
extern void kdba_longjmp(kdb_jmp_buf *, int);

extern kdb_jmp_buf  kdbjmpbuf[];
#endif	/* KDB_HAVE_LONGJMP */

#endif	/* !_ASM_KDBPRIVATE_H */
