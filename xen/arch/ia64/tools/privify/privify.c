/*
 * Binary translate privilege-sensitive ops to privileged
 *
 * Copyright (C) 2004 Hewlett-Packard Co.
 *      Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include "privify.h"

typedef unsigned long long u64;
typedef unsigned long long IA64_INST;

typedef union U_IA64_BUNDLE {
    u64 i64[2];
    struct { u64 template:5,slot0:41,slot1a:18,slot1b:23,slot2:41; };
    // NOTE: following doesn't work because bitfields can't cross natural
    // size boundaries
    //struct { u64 template:5, slot0:41, slot1:41, slot2:41; };
} IA64_BUNDLE;

typedef enum E_IA64_SLOT_TYPE { I, M, F, B, L, ILLEGAL } IA64_SLOT_TYPE;

typedef union U_INST64_A5 {
    IA64_INST inst;
    struct { u64 qp:6, r1:7, imm7b:7, r3:2, imm5c:5, imm9d:9, s:1, major:4; };
} INST64_A5;

typedef union U_INST64_B4 {
    IA64_INST inst;
    struct { u64 qp:6, btype:3, un3:3, p:1, b2:3, un11:11, x6:6, wh:2, d:1, un1:1, major:4; };
} INST64_B4;

typedef union U_INST64_B8 {
    IA64_INST inst;
    struct { u64 qp:6, un21:21, x6:6, un4:4, major:4; };
} INST64_B8;

typedef union U_INST64_B9 {
    IA64_INST inst;
    struct { u64 qp:6, imm20:20, :1, x6:6, :3, i:1, major:4; };
} INST64_B9;

typedef union U_INST64_I19 {
    IA64_INST inst;
    struct { u64 qp:6, imm20:20, :1, x6:6, x3:3, i:1, major:4; };
} INST64_I19;

typedef union U_INST64_I26 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, ar3:7, x6:6, x3:3, :1, major:4;};
} INST64_I26;

typedef union U_INST64_I27 {
    IA64_INST inst;
    struct { u64 qp:6, :7, imm:7, ar3:7, x6:6, x3:3, s:1, major:4;};
} INST64_I27;

typedef union U_INST64_I28 { // not privileged (mov from AR)
    IA64_INST inst;
    struct { u64 qp:6, r1:7, :7, ar3:7, x6:6, x3:3, :1, major:4;};
} INST64_I28;

typedef union U_INST64_M28 {
    IA64_INST inst;
    struct { u64 qp:6, :14, r3:7, x6:6, x3:3, :1, major:4;};
} INST64_M28;

typedef union U_INST64_M29 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, ar3:7, x6:6, x3:3, :1, major:4;};
} INST64_M29;

typedef union U_INST64_M30 {
    IA64_INST inst;
    struct { u64 qp:6, :7, imm:7, ar3:7,x4:4,x2:2,x3:3,s:1,major:4;};
} INST64_M30;

typedef union U_INST64_M31 {
    IA64_INST inst;
    struct { u64 qp:6, r1:7, :7, ar3:7, x6:6, x3:3, :1, major:4;};
} INST64_M31;

typedef union U_INST64_M32 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, cr3:7, x6:6, x3:3, :1, major:4;};
} INST64_M32;

typedef union U_INST64_M33 {
    IA64_INST inst;
    struct { u64 qp:6, r1:7, :7, cr3:7, x6:6, x3:3, :1, major:4; };
} INST64_M33;

typedef union U_INST64_M35 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, :7, x6:6, x3:3, :1, major:4; };
    	
} INST64_M35;

typedef union U_INST64_M36 {
    IA64_INST inst;
    struct { u64 qp:6, r1:7, :14, x6:6, x3:3, :1, major:4; }; 
} INST64_M36;

typedef union U_INST64_M41 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, :7, x6:6, x3:3, :1, major:4; }; 
} INST64_M41;

typedef union U_INST64_M42 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, r3:7, x6:6, x3:3, :1, major:4; };
} INST64_M42;

typedef union U_INST64_M43 {
    IA64_INST inst;
    struct { u64 qp:6, r1:7, :7, r3:7, x6:6, x3:3, :1, major:4; };
} INST64_M43;

typedef union U_INST64_M44 {
    IA64_INST inst;
    struct { u64 qp:6, imm:21, x4:4, i2:2, x3:3, i:1, major:4; };
} INST64_M44;

typedef union U_INST64_M45 {
    IA64_INST inst;
    struct { u64 qp:6, :7, r2:7, r3:7, x6:6, x3:3, :1, major:4; };
} INST64_M45;

typedef union U_INST64_M46 {
    IA64_INST inst;
    struct { u64 qp:6, r1:7, un7:7, r3:7, x6:6, x3:3, un1:1, major:4; };
} INST64_M46;

typedef union U_INST64 {
    IA64_INST inst;
    struct { u64 :37, major:4; } generic;
    INST64_A5 A5;	// used in build_hypercall_bundle only
    INST64_B4 B4;	// used in build_hypercall_bundle only
    INST64_B8 B8;	// rfi, bsw.[01]
    INST64_B9 B9;	// break.b
    INST64_I19 I19;	// used in build_hypercall_bundle only
    INST64_I26 I26;	// mov register to ar (I unit)
    INST64_I27 I27;	// mov immediate to ar (I unit)
    INST64_I28 I28;	// mov from ar (I unit)
    INST64_M28 M28;	// purge translation cache entry
    INST64_M29 M29;	// mov register to ar (M unit)
    INST64_M30 M30;	// mov immediate to ar (M unit)
    INST64_M31 M31;	// mov from ar (M unit)
    INST64_M32 M32;	// mov reg to cr
    INST64_M33 M33;	// mov from cr
    INST64_M35 M35;	// mov to psr
    INST64_M36 M36;	// mov from psr
    INST64_M41 M41;	// translation cache insert
    INST64_M42 M42;	// mov to indirect reg/translation reg insert
    INST64_M43 M43;	// mov from indirect reg
    INST64_M44 M44;	// set/reset system mask
    INST64_M45 M45;	// translation purge
    INST64_M46 M46;	// translation access (tpa,tak)
} INST64;

#define MASK_41 ((u64)0x1ffffffffff)

long priv_verbose = 0;
#define verbose(a...) do { if (priv_verbose) printf(a); } while(0)

/*
 * privify_inst
 *
 * Replaces privilege-sensitive instructions (and reads from write-trapping
 * registers) with privileged/trapping instructions as follows:
 *	mov rx=ar.cflg -> mov ar.cflg=r(x+64) [**]
 *	mov rx=ar.ky -> mov ar.ky=r(x+64)
 *	fc rx -> ptc r(x+64)
 *	thash rx=ry -> tak rx=r(y+64)
 *	ttag rx=ry -> tpa rx=r(y+64)
 *	mov rx=cpuid[ry] -> mov r(x+64)=rr[ry]
 *	mov rx=pmd[ry] -> mov r(x+64)=pmc[ry] [**]
 *	cover -> break.b 0x1fffff
 *
 * [**] not currently implemented
 */
IA64_INST privify_inst(IA64_INST inst_val,
		IA64_SLOT_TYPE slot_type, IA64_BUNDLE *bp, char **msg)
{
	INST64 inst = *(INST64 *)&inst_val;

	*msg = 0;
	switch (slot_type) {
	    case M:
		// FIXME: Also use for mov_to/from_ar.cflag (M29/M30) (IA32 only)
		if (inst.generic.major != 1) break;
		if (inst.M46.x3 != 0) break;
		if (inst.M31.x6 == 0x22 && inst.M31.ar3 < 8) {
			// mov r1=kr -> mov kr=r1+64
			verbose("privify_inst: privified mov r1=kr @%p\n",bp);
			if (inst.M31.r1 >= 64) *msg = "mov r1=kr w/r1>63";
			else privify_mov_from_kr_m(inst);
			break;
		}
		if (inst.M29.x6 == 0x2a && inst.M29.ar3 < 8)  {// mov kr=r1
			if (inst.M29.r2 >= 64) *msg = "mov kr=r2 w/r2>63";
			break;
		}
		if (inst.M28.x6 == 0x30) {
			// fc r3-> ptc r3+64
			verbose("privify_inst: privified fc r3 @%p\n",bp);
			if (inst.M28.r3 >= 64) *msg = "fc r3 w/r3>63";
			else privify_fc(inst);
			break;
		}
		if (inst.M28.x6 == 0x34) {
			if (inst.M28.r3 >= 64) *msg = "ptc.e w/r3>63";
			break;
		}
		if (inst.M46.un7 != 0) break;
		if (inst.M46.un1 != 0) break;
		if (inst.M46.x6 == 0x1a)  { // thash -> tak r1=r3+64
			verbose("privify_inst: privified thash @%p\n",bp);
			if (inst.M46.r3 >= 64) *msg = "thash w/r3>63";
			else privify_thash(inst);
		}
		else if (inst.M46.x6 == 0x1b)  { // ttag -> tpa r1=r3+64
			verbose("privify_inst: privified ttag @%p\n",bp);
			if (inst.M46.r3 >= 64) *msg = "ttag w/r3>63";
			else privify_ttag(inst);
		}
		else if (inst.M43.x6 == 0x17) {
			verbose("privify_inst: privified mov_from_cpuid @%p\n",bp);
			if (inst.M43.r1 >= 64) *msg = "mov_from_cpuid w/r1>63";
			else privify_mov_from_cpuid(inst);
		}
		else if (inst.M46.x6 == 0x1e)  { // tpa
			if (inst.M46.r3 >= 64) *msg = "tpa w/r3>63";
		}
		else if (inst.M46.x6 == 0x1f)  { // tak
			if (inst.M46.r3 >= 64) *msg = "tak w/r3>63";
		}
		else if (inst.M43.x6 == 0x10) {
			if (inst.M43.r1 >= 64) *msg = "mov_to_rr w/r1>63";
		}
		break;
	    case B:
		if (inst.generic.major != 0) break;
		if (inst.B8.x6 == 0x2) { // cover -> break.b 0x1fffff
			if (inst.B8.un21 != 0) break;
			if (inst.B8.un4 != 0) break;
			privify_cover(inst);
			verbose("privify_inst: privified cover @%p\n",bp);
		}
		if (inst.B9.x6 == 0x0) { // (p15) break.b 0x1fffff -> cover
			if (inst.B9.qp != 15) break;
			if (inst.B9.imm20 != 0xfffff) break;
			if (inst.B9.i != 1) break;
			inst.B8.x6 = 0x2;
			inst.B8.un21 = 0;
			inst.B8.un4 = 0;
			inst.B8.qp = 0;
			verbose("privify_inst: unprivified pseudo-cover @%p\n",
					bp);
		}
		break;
	    case I:	// only used for privifying mov_from_ar
		// FIXME: Also use for mov_to/from_ar.cflag (I26/I27) (IA32 only)
		if (inst.generic.major != 0) break;
		if (inst.I28.x6 == 0x32 && !inst.I28.x3 && inst.I28.ar3 < 8) {
			// mov r1=kr -> mov kr=r1+64
			verbose("privify_inst: privified mov r1=kr @%p\n",bp);
			if (inst.I28.r1 >= 64) *msg = "mov r1=kr w/r1>63";
			else privify_mov_from_kr_i(inst);
		}
		else if (inst.I26.x6 == 0x2a && !inst.I26.x3 &&
		    inst.I26.ar3 < 8)  {// mov kr=r1
			if (inst.I26.r2 >= 64) *msg = "mov kr=r2 w/r2>63";
		}
		break;
	    case F: case L: case ILLEGAL:
		break;
	}
	return *(IA64_INST *)&inst;
}

#define read_slot1(b)	    (((b.i64[0]>>46L) | (b.i64[1]<<18UL)) & MASK_41)
// Not sure why, but this more obvious definition of read_slot1 doesn't work
// because the compiler treats (b.slot1b<<18UL) as a signed 32-bit integer
// so not enough bits get used and it gets sign extended to boot!
//#define read_slot1(b)	    ((b.slot1a | (b.slot1b<<18UL)) & MASK_41)
#define write_slot1(b,inst) do { b.slot1a=inst;b.slot1b=inst>>18UL;} while (0)


void privify_memory(void *start, unsigned long len)
{
	IA64_BUNDLE bundle, *bp = (IA64_BUNDLE *)start;
	IA64_INST tmp;
	char *msg;

printf("privifying %ld bytes of memory at %p\n",len,start);
	if ((unsigned long)start & 0xfL) {
		printf("unaligned memory block in privify_memory\n");
	}
	len &= ~0xf;
	for (bundle = *bp; len; len -= 16) {
	    switch(bundle.template) {
		case 0x06: case 0x07: case 0x14: case 0x15:
		case 0x1a: case 0x1b: case 0x1e: case 0x1f:
			break;
		case 0x16: case 0x17:
			// may be B in slot0/1 but cover can only be slot2
			bundle.slot2 = privify_inst(bundle.slot2,B,bp,&msg);
			break;
		case 0x00: case 0x01: case 0x02: case 0x03:
			tmp = privify_inst(read_slot1(bundle),I,bp,&msg);
			write_slot1(bundle,tmp);
		case 0x0c: case 0x0d:
			bundle.slot2 = privify_inst(bundle.slot2,I,bp,&msg);
		case 0x04: case 0x05:
			// could a privified cover be in slot2 here?
			bundle.slot0 = privify_inst(bundle.slot0,M,bp,&msg);
			break;
		case 0x08: case 0x09: case 0x0a: case 0x0b:
			bundle.slot2 = privify_inst(bundle.slot2,I,bp,&msg);
		case 0x0e: case 0x0f:
			bundle.slot0 = privify_inst(bundle.slot0,M,bp,&msg);
			if (msg) break;
			tmp = privify_inst(read_slot1(bundle),M,bp,&msg);
			write_slot1(bundle,tmp);
			break;
		case 0x10: case 0x11:
			tmp = privify_inst(read_slot1(bundle),I,bp,&msg);
			write_slot1(bundle,tmp);
		case 0x12: case 0x13:
			// may be B in slot1 but cover can only be slot2
		case 0x1c: case 0x1d:
			bundle.slot0 = privify_inst(bundle.slot0,M,bp,&msg);
			if (msg) break;
			bundle.slot2 = privify_inst(bundle.slot2,B,bp,&msg);
			break;
		case 0x18: case 0x19:
			bundle.slot0 = privify_inst(bundle.slot0,M,bp,&msg);
			if (msg) break;
			tmp = privify_inst(read_slot1(bundle),M,bp,&msg);
			write_slot1(bundle,tmp);
			if (msg) break;
			bundle.slot2 = privify_inst(bundle.slot2,B,bp,&msg);
			break;
	    }
	    if (msg) {
		if (bundle.slot2)
			printf("privify_memory: %s @%p\n",msg,bp);
		else
			printf("privify_memory: %s @%p probably not insts\n",
				msg,bp);
		printf("privify_memory: bundle=%p,%p\n",
			bundle.i64[1],bundle.i64[0]);
	    }
	    *bp = bundle;
	    bundle = *++bp;
	}

}
