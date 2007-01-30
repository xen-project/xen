/*
 * ia64-specific cdb routines
 * cdb xen/ia64 by Isaku Yamahta <yamahata at valinux co jp>
 *                 VA Linux Systems Japan K.K.
 *  some routines are stolen from kgdb/ia64.
 */
/*
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

/*
 * Copyright (C) 2000-2001 VERITAS Software Corporation.
 */
/*
 *  Contributor:     Lake Stevens Instrument Division$
 *  Written by:      Glenn Engel $
 *  Updated by:	     Amit Kale<akale@veritas.com>
 *  Modified for 386 by Jim Kingdon, Cygnus Support.
 *  Origianl kgdb, compatibility with 2.1.xx kernel by David Grothe <dave@gcom.com>
 *
 */


#include <xen/lib.h>
#include <xen/mm.h>
#include <asm/byteorder.h>
#include <asm/debugger.h>
#include <asm/uaccess.h>

#define USE_UNWIND

#ifdef USE_UNWIND
#include <asm/unwind.h>
#endif

/* Printk isn't particularly safe just after we've trapped to the
   debugger. so avoid it. */
#define dbg_printk(...)
//#define dbg_printk(...)	printk(__VA_ARGS__)

u16
gdb_arch_signal_num(struct cpu_user_regs *regs, unsigned long cookie)
{
    /* XXX */
    return 1;
}

void 
gdb_arch_read_reg_array(struct cpu_user_regs *regs, struct gdb_context *ctx)
{
    gdb_send_reply("", ctx);
}

void 
gdb_arch_write_reg_array(struct cpu_user_regs *regs, const char* buf,
                         struct gdb_context *ctx)
{
    /* XXX TODO */
    gdb_send_reply("E02", ctx);
}

/* Like copy_from_user, but safe to call with interrupts disabled.
   Trust me, and don't look behind the curtain. */
unsigned
gdb_arch_copy_from_user(void *dest, const void *src, unsigned len)
{
	int val;
	__asm__ __volatile__(
		"cmp4.eq p6, p0 = r0, %1\n"
		"(p6) br.cond.dptk 2f\n"
		"[1:]\n"
		".xdata4 \"__ex_table\", 99f-., 2f-.;\n"
		"[99:] ld1 %0 = [%3], 1\n"
		";;\n"
		".xdata4 \"__ex_table\", 99f-., 2f-.;\n"
		"[99:] st1 [%2] = %0, 1\n"
		"adds %1 = -1, %1\n"
		";;\n"
		"cmp4.eq p0, p6 = r0, %1\n"
		"(p6) br.cond.dptk 1b\n"
		"[2:]\n"
		: "=r"(val), "=r"(len), "=r"(dest), "=r"(src)
		:  "1"(len), "2"(dest), "3"(src)
		: "memory", "p6");
	return len;
}

unsigned int 
gdb_arch_copy_to_user(void *dest, const void *src, unsigned len)
{
    /* XXX  */
    return len;
}

#define NUM_REGS 590
#define REGISTER_BYTES (NUM_REGS*8+128*8)
#define REGISTER_BYTE(N) (((N) * 8)									\
	+ ((N) <= IA64_FR0_REGNUM ?                                     \
	0 : 8 * (((N) > IA64_FR127_REGNUM) ? 128 : (N) - IA64_FR0_REGNUM)))
#define REGISTER_SIZE(N)                                               \
	(((N) >= IA64_FR0_REGNUM && (N) <= IA64_FR127_REGNUM) ? 16 : 8)
#define IA64_GR0_REGNUM         0
#define IA64_FR0_REGNUM         128
#define IA64_FR127_REGNUM       (IA64_FR0_REGNUM+127)
#define IA64_PR0_REGNUM         256
#define IA64_BR0_REGNUM         320
#define IA64_VFP_REGNUM         328
#define IA64_PR_REGNUM          330
#define IA64_IP_REGNUM          331
#define IA64_PSR_REGNUM         332
#define IA64_CFM_REGNUM         333
#define IA64_AR0_REGNUM         334
#define IA64_NAT0_REGNUM        462
#define IA64_NAT31_REGNUM       (IA64_NAT0_REGNUM+31)
#define IA64_NAT32_REGNUM       (IA64_NAT0_REGNUM+32)
#define IA64_RSC_REGNUM			(IA64_AR0_REGNUM+16)
#define IA64_BSP_REGNUM			(IA64_AR0_REGNUM+17)
#define IA64_BSPSTORE_REGNUM	(IA64_AR0_REGNUM+18)
#define IA64_RNAT_REGNUM		(IA64_AR0_REGNUM+19)
#define IA64_FCR_REGNUM			(IA64_AR0_REGNUM+21)
#define IA64_EFLAG_REGNUM		(IA64_AR0_REGNUM+24)
#define IA64_CSD_REGNUM			(IA64_AR0_REGNUM+25)
#define IA64_SSD_REGNUM			(IA64_AR0_REGNUM+26)
#define IA64_CFLG_REGNUM		(IA64_AR0_REGNUM+27)
#define IA64_FSR_REGNUM			(IA64_AR0_REGNUM+28)
#define IA64_FIR_REGNUM			(IA64_AR0_REGNUM+29)
#define IA64_FDR_REGNUM			(IA64_AR0_REGNUM+30)
#define IA64_CCV_REGNUM			(IA64_AR0_REGNUM+32)
#define IA64_UNAT_REGNUM		(IA64_AR0_REGNUM+36)
#define IA64_FPSR_REGNUM		(IA64_AR0_REGNUM+40)
#define IA64_ITC_REGNUM			(IA64_AR0_REGNUM+44)
#define IA64_PFS_REGNUM			(IA64_AR0_REGNUM+64)
#define IA64_LC_REGNUM			(IA64_AR0_REGNUM+65)
#define IA64_EC_REGNUM			(IA64_AR0_REGNUM+66)

#ifndef USE_UNWIND
struct regs_to_cpu_user_resgs_index {
	unsigned int reg;
	unsigned int ptregoff;
};

#define ptoff(V)		((unsigned int)&((struct cpu_user_regs*)0x0)->V)

// gr
static const struct regs_to_cpu_user_resgs_index
gr_reg_to_cpu_user_regs_index[] = {
	{IA64_GR0_REGNUM + 8,  ptoff(r8)},
	{IA64_GR0_REGNUM + 9,  ptoff(r9)},
	{IA64_GR0_REGNUM + 10, ptoff(r10)},
	{IA64_GR0_REGNUM + 11, ptoff(r11)},
	{IA64_GR0_REGNUM + 1,  ptoff(r1)},
	{IA64_GR0_REGNUM + 12, ptoff(r12)},
	{IA64_GR0_REGNUM + 13, ptoff(r13)},
	{IA64_GR0_REGNUM + 15, ptoff(r15)},

	{IA64_GR0_REGNUM + 14, ptoff(r14)},
	{IA64_GR0_REGNUM + 2,  ptoff(r2)},
	{IA64_GR0_REGNUM + 3,  ptoff(r3)},
	{IA64_GR0_REGNUM + 16, ptoff(r16)},
	{IA64_GR0_REGNUM + 17, ptoff(r17)},
	{IA64_GR0_REGNUM + 18, ptoff(r18)},
	{IA64_GR0_REGNUM + 19, ptoff(r19)},
	{IA64_GR0_REGNUM + 20, ptoff(r20)},
	{IA64_GR0_REGNUM + 21, ptoff(r21)},
	{IA64_GR0_REGNUM + 22, ptoff(r22)},
	{IA64_GR0_REGNUM + 23, ptoff(r23)},
	{IA64_GR0_REGNUM + 24, ptoff(r24)},
	{IA64_GR0_REGNUM + 25, ptoff(r25)},
	{IA64_GR0_REGNUM + 26, ptoff(r26)},
	{IA64_GR0_REGNUM + 27, ptoff(r27)},
	{IA64_GR0_REGNUM + 28, ptoff(r28)},
	{IA64_GR0_REGNUM + 29, ptoff(r29)},
	{IA64_GR0_REGNUM + 30, ptoff(r30)},
	{IA64_GR0_REGNUM + 31, ptoff(r31)},

	{IA64_GR0_REGNUM + 4,  ptoff(r4)},
	{IA64_GR0_REGNUM + 5,  ptoff(r5)},
	{IA64_GR0_REGNUM + 6,  ptoff(r6)},
	{IA64_GR0_REGNUM + 7,  ptoff(r7)},
};
static const int gr_reg_to_cpu_user_regs_index_max =
	sizeof(gr_reg_to_cpu_user_regs_index) /
	sizeof(gr_reg_to_cpu_user_regs_index[0]); 

// br
static const struct regs_to_cpu_user_resgs_index
br_reg_to_cpu_user_regs_index[] = {
	{IA64_BR0_REGNUM + 0, ptoff(b0)},
	{IA64_BR0_REGNUM + 6, ptoff(b6)},
	{IA64_BR0_REGNUM + 7, ptoff(b7)},
};
static const int br_reg_to_cpu_user_regs_index_max =
	sizeof(br_reg_to_cpu_user_regs_index) /
	sizeof(br_reg_to_cpu_user_regs_index[0]); 

// f
static const struct regs_to_cpu_user_resgs_index
fr_reg_to_cpu_user_regs_index[] = {
	{IA64_FR0_REGNUM + 6,  ptoff(f6)},
	{IA64_FR0_REGNUM + 7,  ptoff(f7)},
	{IA64_FR0_REGNUM + 8,  ptoff(f8)},
	{IA64_FR0_REGNUM + 9,  ptoff(f9)},
	{IA64_FR0_REGNUM + 10, ptoff(f10)},
	{IA64_FR0_REGNUM + 11, ptoff(f11)},
};
static const int fr_reg_to_cpu_user_regs_index_max =
	sizeof(fr_reg_to_cpu_user_regs_index) /
	sizeof(fr_reg_to_cpu_user_regs_index[0]); 
	

void 
gdb_arch_read_reg(unsigned long regnum, struct cpu_user_regs *regs,
                  struct gdb_context *ctx)
{
	unsigned long reg = IA64_IP_REGNUM;
	char buf[9];
	int i;

	dbg_printk("Register read regnum = 0x%lx\n", regnum);
	if (IA64_GR0_REGNUM <= regnum && regnum <= IA64_GR0_REGNUM + 31) {
		for (i = 0; i < gr_reg_to_cpu_user_regs_index_max; i++) {
			if (gr_reg_to_cpu_user_regs_index[i].reg == regnum) {
				reg = *(unsigned long*)(((char*)regs) + gr_reg_to_cpu_user_regs_index[i].ptregoff);
				break;
			}
		}
		if (i == gr_reg_to_cpu_user_regs_index_max) {
			goto out_err;
		}
	} else if (IA64_BR0_REGNUM <= regnum && regnum <= IA64_BR0_REGNUM + 7) {
		for (i = 0; i < br_reg_to_cpu_user_regs_index_max; i++) {
			if (br_reg_to_cpu_user_regs_index[i].reg == regnum) {
				reg = *(unsigned long*)(((char*)regs) + br_reg_to_cpu_user_regs_index[i].ptregoff);
				break;
			}
		}
		if (i == br_reg_to_cpu_user_regs_index_max) {
			goto out_err;
		}
	} else if (IA64_FR0_REGNUM + 6 <= regnum && regnum <= IA64_FR0_REGNUM + 11) {
		for (i = 0; i < fr_reg_to_cpu_user_regs_index_max; i++) {
			if (fr_reg_to_cpu_user_regs_index[i].reg == regnum) {
				reg = *(unsigned long*)(((char*)regs) + fr_reg_to_cpu_user_regs_index[i].ptregoff);
				break;
			}
		}
		if (i == fr_reg_to_cpu_user_regs_index_max) {
			goto out_err;
		}
	} else if (regnum == IA64_CSD_REGNUM) {
		reg = regs->ar_csd;
	} else if (regnum == IA64_SSD_REGNUM) {
		reg = regs->ar_ssd;
	} else if (regnum == IA64_PSR_REGNUM) {
		reg = regs->cr_ipsr;
	} else if (regnum == IA64_IP_REGNUM) {
		reg = regs->cr_iip;
	} else if (regnum == IA64_CFM_REGNUM) {
		reg = regs->cr_ifs;
	} else if (regnum == IA64_UNAT_REGNUM) {
		reg = regs->ar_unat;
	} else if (regnum == IA64_PFS_REGNUM) {
		reg = regs->ar_pfs;
	} else if (regnum == IA64_RSC_REGNUM) {
		reg = regs->ar_rsc;
	} else if (regnum == IA64_RNAT_REGNUM) {
		reg = regs->ar_rnat;
	} else if (regnum == IA64_BSPSTORE_REGNUM) {
		reg = regs->ar_bspstore;
	} else if (regnum == IA64_PR_REGNUM) {
		reg = regs->pr;
	} else if (regnum == IA64_FPSR_REGNUM) {
		reg = regs->ar_fpsr;
	} else if (regnum == IA64_CCV_REGNUM) {
		reg = regs->ar_ccv;
	} else {
		// emul_unat, rfi_pfs
		goto out_err;
	}

	dbg_printk("Register read regnum = 0x%lx, val = 0x%lx\n", regnum, reg);	
	snprintf(buf, sizeof(buf), "%.08lx", swab64(reg));
out:
	return gdb_send_reply(buf, ctx);

out_err:
	dbg_printk("Register read unsupported regnum = 0x%lx\n", regnum);
	safe_strcpy(buf, "x");
	goto out;
}
#else

#define	ptoff(V)	((unsigned int) &((struct pt_regs *)0x0)->V)
struct reg_to_ptreg_index {
	unsigned int reg;
	unsigned int ptregoff;
};

static struct reg_to_ptreg_index gr_reg_to_ptreg_index[] = {
	{IA64_GR0_REGNUM + 1, ptoff(r1)},
	{IA64_GR0_REGNUM + 2, ptoff(r2)},
	{IA64_GR0_REGNUM + 3, ptoff(r3)},
	{IA64_GR0_REGNUM + 8, ptoff(r8)},
	{IA64_GR0_REGNUM + 9, ptoff(r9)},
	{IA64_GR0_REGNUM + 10, ptoff(r10)},
	{IA64_GR0_REGNUM + 11, ptoff(r11)},
	{IA64_GR0_REGNUM + 12, ptoff(r12)},
	{IA64_GR0_REGNUM + 13, ptoff(r13)},
	{IA64_GR0_REGNUM + 14, ptoff(r14)},
	{IA64_GR0_REGNUM + 15, ptoff(r15)},
	{IA64_GR0_REGNUM + 16, ptoff(r16)},
	{IA64_GR0_REGNUM + 17, ptoff(r17)},
	{IA64_GR0_REGNUM + 18, ptoff(r18)},
	{IA64_GR0_REGNUM + 19, ptoff(r19)},
	{IA64_GR0_REGNUM + 20, ptoff(r20)},
	{IA64_GR0_REGNUM + 21, ptoff(r21)},
	{IA64_GR0_REGNUM + 22, ptoff(r22)},
	{IA64_GR0_REGNUM + 23, ptoff(r23)},
	{IA64_GR0_REGNUM + 24, ptoff(r24)},
	{IA64_GR0_REGNUM + 25, ptoff(r25)},
	{IA64_GR0_REGNUM + 26, ptoff(r26)},
	{IA64_GR0_REGNUM + 27, ptoff(r27)},
	{IA64_GR0_REGNUM + 28, ptoff(r28)},
	{IA64_GR0_REGNUM + 29, ptoff(r29)},
	{IA64_GR0_REGNUM + 30, ptoff(r30)},
	{IA64_GR0_REGNUM + 31, ptoff(r31)},
};

static struct reg_to_ptreg_index br_reg_to_ptreg_index[] = {
	{IA64_BR0_REGNUM, ptoff(b0)},
	{IA64_BR0_REGNUM + 6, ptoff(b6)},
	{IA64_BR0_REGNUM + 7, ptoff(b7)},
};

static struct reg_to_ptreg_index ar_reg_to_ptreg_index[] = {
	{IA64_PFS_REGNUM, ptoff(ar_pfs)},
	{IA64_UNAT_REGNUM, ptoff(ar_unat)},
	{IA64_RNAT_REGNUM, ptoff(ar_rnat)},
	{IA64_BSPSTORE_REGNUM, ptoff(ar_bspstore)},
	{IA64_RSC_REGNUM, ptoff(ar_rsc)},
	{IA64_CSD_REGNUM, ptoff(ar_csd)},
	{IA64_SSD_REGNUM, ptoff(ar_ssd)},
	{IA64_FPSR_REGNUM, ptoff(ar_fpsr)},
	{IA64_CCV_REGNUM, ptoff(ar_ccv)},
};

#ifndef XEN
extern atomic_t cpu_doing_single_step;
#endif

static int kgdb_gr_reg(int regnum, struct unw_frame_info *info,
	unsigned long *reg, int rw)
{
	char nat;

	if ((regnum >= IA64_GR0_REGNUM && regnum <= (IA64_GR0_REGNUM + 1)) ||
		(regnum >= (IA64_GR0_REGNUM + 4) &&
		regnum <= (IA64_GR0_REGNUM + 7)))
		return !unw_access_gr(info, regnum - IA64_GR0_REGNUM,
		reg, &nat, rw);
	else
		return 0;
}
static int kgdb_gr_ptreg(int regnum, struct pt_regs * ptregs,
	struct unw_frame_info *info, unsigned long *reg, int rw)
{
	int i, result = 1;
	char nat;

	if (!((regnum >= (IA64_GR0_REGNUM + 2) &&
		regnum <= (IA64_GR0_REGNUM + 3)) ||
		(regnum >= (IA64_GR0_REGNUM + 8) &&
		regnum <= (IA64_GR0_REGNUM + 15)) ||
		(regnum >= (IA64_GR0_REGNUM + 16) &&
		regnum <= (IA64_GR0_REGNUM + 31))))
		return 0;
	else if (rw && ptregs) {
		for (i = 0; i < ARRAY_SIZE(gr_reg_to_ptreg_index); i++)
			if (gr_reg_to_ptreg_index[i].reg == regnum) {
				*((unsigned long *)(((void *)ptregs) +
				gr_reg_to_ptreg_index[i].ptregoff)) = *reg;
				break;
			}
	} else if (!rw && ptregs) {
		for (i = 0; i < ARRAY_SIZE(gr_reg_to_ptreg_index); i++)
			if (gr_reg_to_ptreg_index[i].reg == regnum) {
				*reg = *((unsigned long *)
				(((void *)ptregs) +
				 gr_reg_to_ptreg_index[i].ptregoff));
				break;
			}
	} else
		result = !unw_access_gr(info, regnum - IA64_GR0_REGNUM,
					reg, &nat, rw);
	return result;
}

static int kgdb_br_reg(int regnum, struct pt_regs * ptregs,
	struct unw_frame_info *info, unsigned long *reg, int rw)
{
	int i, result = 1;

	if (!(regnum >= IA64_BR0_REGNUM && regnum <= (IA64_BR0_REGNUM + 7)))
		return 0;

	switch (regnum) {
	case IA64_BR0_REGNUM:
	case IA64_BR0_REGNUM + 6:
	case IA64_BR0_REGNUM + 7:
		if (rw) {
			for (i = 0; i < ARRAY_SIZE(br_reg_to_ptreg_index); i++)
				if (br_reg_to_ptreg_index[i].reg == regnum) {
					*((unsigned long *)
					(((void *)ptregs) +
					br_reg_to_ptreg_index[i].ptregoff)) =
					*reg;
					break;
				}
		} else
			for (i = 0; i < ARRAY_SIZE(br_reg_to_ptreg_index); i++)
				if (br_reg_to_ptreg_index[i].reg == regnum) {
						*reg = *((unsigned long *)
						(((void *)ptregs) +
						br_reg_to_ptreg_index[i].
						ptregoff));
						break;
				}
		break;
	case IA64_BR0_REGNUM + 1:
	case IA64_BR0_REGNUM + 2:
	case IA64_BR0_REGNUM + 3:
	case IA64_BR0_REGNUM + 4:
	case IA64_BR0_REGNUM + 5:
		result = !unw_access_br(info, regnum - IA64_BR0_REGNUM,
				reg, rw);
		break;
	}

	return result;
}

static int kgdb_fr_reg(int regnum, char *inbuffer, struct pt_regs * ptregs,
	struct unw_frame_info *info, unsigned long *reg,
	struct ia64_fpreg *freg, int rw)
{
	int result = 1;

	if (!(regnum >= IA64_FR0_REGNUM && regnum <= (IA64_FR0_REGNUM + 127)))
		return 0;

	switch (regnum) {
	case IA64_FR0_REGNUM + 6:
	case IA64_FR0_REGNUM + 7:
	case IA64_FR0_REGNUM + 8:
	case IA64_FR0_REGNUM + 9:
	case IA64_FR0_REGNUM + 10:
	case IA64_FR0_REGNUM + 11:
	case IA64_FR0_REGNUM + 12:
		if (rw) {
#ifndef XEN
			char *ptr = inbuffer;

			freg->u.bits[0] = *reg;
			kgdb_hex2long(&ptr, &freg->u.bits[1]);
			*(&ptregs->f6 + (regnum - (IA64_FR0_REGNUM + 6))) =
				*freg;
#else
			printk("%s: %d: writing to fpreg is not supported.\n",
				   __func__, __LINE__);
#endif
			break;
		} else if (!ptregs)
			result = !unw_access_fr(info, regnum - IA64_FR0_REGNUM,
				freg, rw);
		else
#ifndef XEN
			*freg =
			*(&ptregs->f6 + (regnum - (IA64_FR0_REGNUM + 6)));
#else
		    //XXX struct ia64_fpreg and struct pt_fpreg are same.
			*freg = *((struct ia64_fpreg*)(&ptregs->f6 +
										   (regnum - (IA64_FR0_REGNUM + 6))));
#endif
		break;
	default:
		if (!rw)
			result = !unw_access_fr(info, regnum - IA64_FR0_REGNUM,
				freg, rw);
		else
			result = 0;
		break;
	}

	return result;
}

static int kgdb_ar_reg(int regnum, struct pt_regs * ptregs,
	struct unw_frame_info *info, unsigned long *reg, int rw)
{
	int result = 0, i;

	if (!(regnum >= IA64_AR0_REGNUM && regnum <= IA64_EC_REGNUM))
		return 0;

	if (rw && ptregs) {
		for (i = 0; i < ARRAY_SIZE(ar_reg_to_ptreg_index); i++)
			if (ar_reg_to_ptreg_index[i].reg == regnum) {
				*((unsigned long *) (((void *)ptregs) +
				ar_reg_to_ptreg_index[i].ptregoff)) =
					*reg;
				result = 1;
				break;
			}
	} else if (ptregs) {
		for (i = 0; i < ARRAY_SIZE(ar_reg_to_ptreg_index); i++)
			if (ar_reg_to_ptreg_index[i].reg == regnum) {
				*reg = *((unsigned long *) (((void *)ptregs) +
					ar_reg_to_ptreg_index[i].ptregoff));
					result = 1;
				break;
			}
	}

	if (result)
		return result;

       result = 1;

	switch (regnum) {
	case IA64_CSD_REGNUM:
		result = !unw_access_ar(info, UNW_AR_CSD, reg, rw);
		break;
	case IA64_SSD_REGNUM:
		result = !unw_access_ar(info, UNW_AR_SSD, reg, rw);
		break;
	case IA64_UNAT_REGNUM:
		result = !unw_access_ar(info, UNW_AR_RNAT, reg, rw);
		break;
		case IA64_RNAT_REGNUM:
		result = !unw_access_ar(info, UNW_AR_RNAT, reg, rw);
		break;
	case IA64_BSPSTORE_REGNUM:
		result = !unw_access_ar(info, UNW_AR_RNAT, reg, rw);
		break;
	case IA64_PFS_REGNUM:
		result = !unw_access_ar(info, UNW_AR_RNAT, reg, rw);
		break;
	case IA64_LC_REGNUM:
		result = !unw_access_ar(info, UNW_AR_LC, reg, rw);
		break;
	case IA64_EC_REGNUM:
		result = !unw_access_ar(info, UNW_AR_EC, reg, rw);
		break;
	case IA64_FPSR_REGNUM:
		result = !unw_access_ar(info, UNW_AR_FPSR, reg, rw);
		break;
	case IA64_RSC_REGNUM:
		result = !unw_access_ar(info, UNW_AR_RSC, reg, rw);
		break;
	case IA64_CCV_REGNUM:
		result = !unw_access_ar(info, UNW_AR_CCV, reg, rw);
		break;
	default:
		result = 0;
	}

	return result;
}

#ifndef XEN
void kgdb_get_reg(char *outbuffer, int regnum, struct unw_frame_info *info,
	struct pt_regs *ptregs)
#else
static int
kgdb_get_reg(int regnum, struct unw_frame_info *info,
			 struct cpu_user_regs* ptregs,
			 unsigned long* __reg, struct ia64_fpreg* __freg)
#endif
{
	unsigned long reg, size = 0, *mem = &reg;
	struct ia64_fpreg freg;

	if (kgdb_gr_reg(regnum, info, &reg, 0) ||
		kgdb_gr_ptreg(regnum, ptregs, info, &reg, 0) ||
		kgdb_br_reg(regnum, ptregs, info, &reg, 0) ||
		kgdb_ar_reg(regnum, ptregs, info, &reg, 0))
			size = sizeof(reg);
	else if (kgdb_fr_reg(regnum, NULL, ptregs, info, &reg, &freg, 0)) {
		size = sizeof(freg);
		mem = (unsigned long *)&freg;
	} else if (regnum == IA64_IP_REGNUM) {
		if (!ptregs) {
			unw_get_ip(info, &reg);
			size = sizeof(reg);
		} else {
			reg = ptregs->cr_iip;
			size = sizeof(reg);
		}
	} else if (regnum == IA64_CFM_REGNUM) {
		if (!ptregs)
			unw_get_cfm(info, &reg);
		else
			reg = ptregs->cr_ifs;
		size = sizeof(reg);
	} else if (regnum == IA64_PSR_REGNUM) {
#ifndef XEN
		if (!ptregs && kgdb_usethread)
			ptregs = (struct pt_regs *)
			((unsigned long)kgdb_usethread +
			IA64_STK_OFFSET) - 1;
#endif
		if (ptregs)
			reg = ptregs->cr_ipsr;
		size = sizeof(reg);
	} else if (regnum == IA64_PR_REGNUM) {
		if (ptregs)
			reg = ptregs->pr;
		else
			unw_access_pr(info, &reg, 0);
		size = sizeof(reg);
	} else if (regnum == IA64_BSP_REGNUM) {
		unw_get_bsp(info, &reg);
		size = sizeof(reg);
	}

#ifndef XEN
	if (size) {
		kgdb_mem2hex((char *) mem, outbuffer, size);
		outbuffer[size*2] = 0;
	}
	else
		strlcpy(outbuffer, "E0", sizeof("E0"));

	return;
#else
	if (size) {
		if (size == sizeof(reg)) {
			*__reg = reg;
		} else {
			BUG_ON(size != sizeof(freg));
			*__freg = freg;
		}
		return 0;
	}

	return -1;
#endif
}

#ifndef XEN
static int inline kgdb_get_blocked_state(struct task_struct *p,
					 struct unw_frame_info *unw)
#else
static int
kgdb_get_blocked_state(struct vcpu *p,
					   struct cpu_user_regs *regs,
					   struct unw_frame_info *unw)
#endif
{
	unsigned long ip;
	int count = 0;

#ifndef XEN
	unw_init_from_blocked_task(unw, p);
#endif
	ip = 0UL;
	do {
		if (unw_unwind(unw) < 0)
			return -1;
		unw_get_ip(unw, &ip);
#ifndef XEN
		if (!in_sched_functions(ip))
			break;
#else
		dbg_printk("ip 0x%lx cr_iip 0x%lx\n", ip, regs->cr_iip);
		if (ip == regs->cr_iip)
			break;
#endif
	} while (count++ < 16);

	if (!ip)
		return -1;
	else
		return 0;
}

struct gdb_callback_arg
{
	struct cpu_user_regs*		regs;
	unsigned long				regnum;
	unsigned long*				reg;
	struct pt_fpreg*			freg;

	int							error;
	                            //  1: not supported
								//  0: success
								// -1: failure
};

static void
gdb_get_reg_callback(struct unw_frame_info* info, void* __arg)
{
	struct gdb_callback_arg* arg = (struct gdb_callback_arg*)__arg;

	if (kgdb_get_blocked_state(current, arg->regs, info) < 0) {
		dbg_printk("%s: kgdb_get_blocked_state failed\n", __func__);
		arg->error = -1;
		return;
	}
	//XXX struct ia64_fpreg and struct pt_fpreg are same.
	if (kgdb_get_reg(arg->regnum, info, arg->regs, arg->reg, 
					 (struct ia64_fpreg*)arg->freg) < 0) {
		dbg_printk("%s: kgdb_get_reg failed\n", __func__);
		arg->error = 1;
		return;
	}
	arg->error = 0;
	return;
}

void 
gdb_arch_read_reg(unsigned long regnum, struct cpu_user_regs *regs,
                  struct gdb_context *ctx)
{
	struct gdb_callback_arg arg;
	unsigned long reg;
	struct pt_fpreg freg;
	char buf[16 * 2 + 1];

	if (regnum >= NUM_REGS) {
		dbg_printk("%s: regnum %ld\n", __func__, regnum);
		goto out_err;
	}

	arg.regs = regs;
	arg.regnum = regnum;
	arg.reg = &reg;
	arg.freg = &freg;
	arg.error = 0;
	unw_init_running(&gdb_get_reg_callback, (void*)&arg);
	if (arg.error < 0) {
		dbg_printk("%s: gdb_get_reg_callback failed\n", __func__);
		goto out_err;
	}

	if (arg.error > 0) {
		// notify gdb that this register is not supported.
		// see fetch_register_using_p() in gdb/remote.c.
		safe_strcpy(buf, "x");
	} else if (IA64_FR0_REGNUM <= regnum && regnum <= IA64_FR0_REGNUM + 127) {
		snprintf(buf, sizeof(buf), "%.016lx", swab64(freg.u.bits[0]));
		snprintf(buf + 16, sizeof(buf) - 16, "%.016lx", swab64(freg.u.bits[1]));
	} else {
		snprintf(buf, sizeof(buf), "%.016lx", swab64(reg));
	}
out:
	return gdb_send_reply(buf, ctx);

out_err:
	dbg_printk("Register read unsupported regnum = 0x%lx\n", regnum);
	safe_strcpy(buf, "E0");
	goto out;
}
#endif

void 
gdb_arch_resume(struct cpu_user_regs *regs,
                unsigned long addr, unsigned long type,
                struct gdb_context *ctx)
{
    /* XXX */
    if (type == GDB_STEP) {
        gdb_send_reply("S01", ctx);
    }
}

void
gdb_arch_print_state(struct cpu_user_regs *regs)
{
    /* XXX */
}

void
gdb_arch_enter(struct cpu_user_regs *regs)
{
    /* nothing */
}

void
gdb_arch_exit(struct cpu_user_regs *regs)
{
    /* nothing */
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * End:
 */
