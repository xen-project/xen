/*
 * Binary translate privilege-sensitive ops to privileged
 *
 * Copyright (C) 2004 Hewlett-Packard Co.
 *      Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

/*
 * Macros to replace privilege-sensitive instructions (and reads from
 * write-trapping registers) with privileged/trapping instructions as follows:
 *	mov rx=ar.cflg -> mov ar.cflg=r(x+64) [**]
 *	mov rx=ar.ky -> mov ar.ky=r(x+64)
 *	fc rx -> ptc r(x+64)
 *	thash rx=ry -> tak rx=r(y+64)
 *	ttag rx=ry -> tpa rx=r(y+64)
 *	mov rx=cpuid[ry] -> mov r(x+64)=rr[ry]
 *	mov rx=pmd[ry] -> mov r(x+64)=pmc[ry] [**]
 *	cover -> break.b 0x1fffff
 *  [**] not implemented yet
 */

#define notimpl(s) printk(s##" not implemented");
#define privify_mov_from_cflg_m(i) do { notimpl("mov from ar.cflg"); } while(0)
#define privify_mov_from_cflg_i(i) do { notimpl("mov from ar.cflg"); } while(0)
#define privify_mov_from_kr_m(i) do { i.M31.x6 = 0x2a; i.M29.r2 = i.M31.r1 + 64; } while(0)
#define privify_mov_from_kr_i(i) do { i.I28.x6 = 0x2a; i.I26.r2 = i.I28.r1 + 64; } while(0)
#define privify_fc(i) do { i.M28.x6 = 0x34; i.M28.r3 = i.M28.r3 + 64; } while(0)
#define privify_thash(i) do { i.M46.x6 = 0x1f; i.M46.r3 += 64; } while(0)
#define privify_ttag(i) do { i.M46.x6 = 0x1f; i.M46.r3 += 64; } while(0)
#define privify_mov_from_cpuid(i) do { i.M43.x6 = 0x10; i.M43.r1 += 64; } while(0)
#define privify_mov_from_pmd(i) do { notimpl("mov from pmd"); } while(0)
#define privify_cover(x) do { x.B8.x6 = 0x0; x.B9.imm20 = 0xfffff; x.B9.i = 0x1; } while(0)

