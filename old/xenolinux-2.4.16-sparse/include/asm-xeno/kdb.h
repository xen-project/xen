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
 */
#if !defined(_ASM_KDB_H)
#define _ASM_KDB_H

	/*
	 * KDB_ENTER() is a macro which causes entry into the kernel
	 * debugger from any point in the kernel code stream.  If it 
	 * is intended to be used from interrupt level, it must  use
	 * a non-maskable entry method.
	 */
#define KDB_ENTER()	asm("\tint $129\n")

	/*
	 * Define the exception frame for this architeture
	 */
struct pt_regs;
typedef struct pt_regs	*kdb_eframe_t;

	/*
	 * Needed for exported symbols.
	 */
typedef unsigned long kdb_machreg_t;

#define kdb_machreg_fmt		"0x%lx"
#define kdb_machreg_fmt0	"0x%08lx"
#define kdb_bfd_vma_fmt		"0x%lx"
#define kdb_bfd_vma_fmt0	"0x%08lx"
#define kdb_elfw_addr_fmt	"0x%x"
#define kdb_elfw_addr_fmt0	"0x%08x"

	/*
	 * Per cpu arch specific kdb state.  Must be in range 0xff000000.
	 */
#define KDB_STATE_A_IF		0x01000000	/* Saved IF flag */

	 /*
	  * Interface from kernel trap handling code to kernel debugger.
	  */
extern int	kdba_callback_die(struct pt_regs *, int, long, void*);
extern int	kdba_callback_bp(struct pt_regs *, int, long, void*);
extern int	kdba_callback_debug(struct pt_regs *, int, long, void *);

#endif	/* ASM_KDB_H */
