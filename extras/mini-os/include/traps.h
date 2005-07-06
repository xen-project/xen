/* 
 ****************************************************************************
 * (C) 2005 - Grzegorz Milos - Intel Reseach Cambridge
 ****************************************************************************
 *
 *        File: traps.h
 *      Author: Grzegorz Milos (gm281@cam.ac.uk)
 *              
 *        Date: Jun 2005
 * 
 * Environment: Xen Minimal OS
 * Description: Deals with traps
 *
 ****************************************************************************
 */

#ifndef _TRAPS_H_
#define _TRAPS_H_

struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};


void dump_regs(struct pt_regs *regs);

#endif /* _TRAPS_H_ */
