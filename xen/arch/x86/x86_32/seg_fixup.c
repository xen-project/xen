/******************************************************************************
 * arch/x86/x86_32/seg_fixup.c
 * 
 * Support for -ve accesses to pseudo-4GB segments.
 * 
 * Copyright (c) 2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <asm/processor.h>

/* Make the scary benign errors go away. */
#undef  DPRINTK
#define DPRINTK(_f, _a...) ((void)0)

/* General instruction properties. */
#define INSN_SUFFIX_BYTES (7)
#define OPCODE_BYTE       (1<<4)  
#define HAS_MODRM         (1<<5)

/* Short forms for the table. */
#define X  0 /* invalid for some random reason */
#define O  OPCODE_BYTE
#define M  HAS_MODRM

static unsigned char insn_decode[256] = {
    /* 0x00 - 0x0F */
    O|M, O|M, O|M, O|M, X, X, X, X,
    O|M, O|M, O|M, O|M, X, X, X, X,
    /* 0x10 - 0x1F */
    O|M, O|M, O|M, O|M, X, X, X, X,
    O|M, O|M, O|M, O|M, X, X, X, X,
    /* 0x20 - 0x2F */
    O|M, O|M, O|M, O|M, X, X, X, X,
    O|M, O|M, O|M, O|M, X, X, X, X,
    /* 0x30 - 0x3F */
    O|M, O|M, O|M, O|M, X, X, X, X,
    O|M, O|M, O|M, O|M, X, X, X, X,
    /* 0x40 - 0x4F */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0x50 - 0x5F */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0x60 - 0x6F */
    X, X, X, X, X, X, X, X,
    X, O|M|4, X, O|M|1, X, X, X, X,
    /* 0x70 - 0x7F */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0x80 - 0x8F */
    O|M|1, O|M|4, O|M|1, O|M|1, O|M, O|M, O|M, O|M,
    O|M, O|M, O|M, O|M, O|M, O|M, O|M, X,
    /* 0x90 - 0x9F */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0xA0 - 0xAF */
    O|1, O|4, O|1, O|4, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0xB0 - 0xBF */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0xC0 - 0xCF */
    O|M|1, O|M|1, X, X, X, X, O|M|1, O|M|4,
    X, X, X, X, X, X, X, X,
    /* 0xD0 - 0xDF */
    O|M, O|M, O|M, O|M, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0xE0 - 0xEF */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, X, X,
    /* 0xF0 - 0xFF */
    X, X, X, X, X, X, X, X,
    X, X, X, X, X, X, O|M, O|M
};

/*
 * Obtain the base and limit associated with the given segment selector.
 * The selector must identify a 32-bit code or data segment. Any segment that
 * appears to be truncated to not overlap with Xen is assumed to be a truncated
 * 4GB segment, and the returned limit reflects this.
 *  @seg   (IN) : Segment selector to decode.
 *  @base  (OUT): Decoded linear base address.
 *  @limit (OUT): Decoded segment limit, in bytes. 0 == unlimited (4GB).
 */
int get_baselimit(u16 seg, unsigned long *base, unsigned long *limit)
{
    struct domain *d = current;
    unsigned long *table, a, b;
    int            ldt = !!(seg & 4);
    int            idx = (seg >> 3) & 8191;

    /* Get base and check limit. */
    if ( ldt )
    {
        table = (unsigned long *)LDT_VIRT_START;
        if ( idx >= d->mm.ldt_ents )
            goto fail;
    }
    else /* gdt */
    {
        table = (unsigned long *)GET_GDT_ADDRESS(d);
        if ( idx >= GET_GDT_ENTRIES(d) )
            goto fail;
    }

    /* Grab the segment descriptor. */
    if ( __get_user(a, &table[2*idx+0]) ||
         __get_user(b, &table[2*idx+1]) )
        goto fail; /* Barking up the wrong tree. Decode needs a page fault.*/

    /* We only parse 32-bit code and data segments. */
    if ( (b & (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB)) != 
         (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB) )
        goto fail;

    /* Decode base and limit. */
    *base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
    *limit = ((b & 0xf0000) | (a & 0x0ffff)) + 1;
    if ( (b & _SEGMENT_G) )
        *limit <<= 12;

    /*
     * Anything that looks like a truncated segment we assume ought really
     * to be a 4GB segment. DANGER!
     */
    if ( (PAGE_OFFSET - (*base + *limit)) < PAGE_SIZE )
        *limit = 0;

    return 1;

 fail:
    return 0;
}

/* Turn a segment+offset into a linear address. */
int linearise_address(u16 seg, unsigned long off, unsigned long *linear)
{
    unsigned long base, limit;

    if ( !get_baselimit(seg, &base, &limit) )
        return 0;

    if ( off > (limit-1) )
        return 0;

    *linear = base + off;

    return 1;
}

int fixup_seg(u16 seg, int positive_access)
{
    struct domain *d = current;
    unsigned long *table, a, b, base, limit;
    int            ldt = !!(seg & 4);
    int            idx = (seg >> 3) & 8191;

    /* Get base and check limit. */
    if ( ldt )
    {
        table = (unsigned long *)LDT_VIRT_START;
        if ( idx >= d->mm.ldt_ents )
        {
            DPRINTK("Segment %04x out of LDT range (%d)\n",
                    seg, d->mm.ldt_ents);
            goto fail;
        }
    }
    else /* gdt */
    {
        table = (unsigned long *)GET_GDT_ADDRESS(d);
        if ( idx >= GET_GDT_ENTRIES(d) )
        {
            DPRINTK("Segment %04x out of GDT range (%d)\n",
                    seg, GET_GDT_ENTRIES(d));
            goto fail;
        }
    }

    /* Grab the segment descriptor. */
    if ( __get_user(a, &table[2*idx+0]) ||
         __get_user(b, &table[2*idx+1]) )
    {
        DPRINTK("Fault while reading segment %04x\n", seg);
        goto fail; /* Barking up the wrong tree. Decode needs a page fault.*/
    }

    /* We only parse 32-bit page-granularity non-privileged data segments. */
    if ( (b & (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|
               _SEGMENT_G|(1<<11)|_SEGMENT_DPL)) != 
         (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|_SEGMENT_G|_SEGMENT_DPL) )
    {
        DPRINTK("Bad segment %08lx:%08lx\n", a, b);
        goto fail;
    }

    /* Decode base and limit. */
    base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
    limit = (((b & 0xf0000) | (a & 0x0ffff)) + 1) << 12;

    if ( b & (1 << 10) )
    {
        /* Expands-down: All the way to zero? Assume 4GB if so. */
        if ( ((base + limit) < PAGE_SIZE) && positive_access )
        {
            /* Flip to expands-up. */
            limit >>= 12;
            limit -= (-PAGE_OFFSET/PAGE_SIZE) + 2;
            goto flip;
        }
    }
    else
    {
        /* Expands-up: All the way to Xen space? Assume 4GB if so. */
        if ( ((PAGE_OFFSET - (base + limit)) < PAGE_SIZE) && !positive_access )
        {
            /* Flip to expands-down. */
            limit >>= 12;
            limit += (-PAGE_OFFSET/PAGE_SIZE) + 0;
            goto flip;
        }
    }

    DPRINTK("None of the above! (%08lx:%08lx, %d, %08lx, %08lx, %08lx)\n", 
            a, b, positive_access, base, limit, base+limit);

 fail:
    return 0;

 flip:
    a &= ~0x0ffff; a |= limit & 0x0ffff;
    b &= ~0xf0000; b |= limit & 0xf0000;
    b ^= 1 << 10;
    /* NB. These can't fault. Checked readable above; must also be writable. */
    table[2*idx+0] = a;
    table[2*idx+1] = b;
    return 1;
}

/* Decode Reg field of a ModRM byte: return a pointer into a register block. */
void *decode_reg(struct xen_regs *regs, u8 b)
{
    switch ( b & 7 )
    {
    case 0: return &regs->eax;
    case 1: return &regs->ecx;
    case 2: return &regs->edx;
    case 3: return &regs->ebx;
    case 4: return &regs->esp;
    case 5: return &regs->ebp;
    case 6: return &regs->esi;
    case 7: return &regs->edi;
    }

    return NULL;
}

/*
 * Called from the general-protection fault handler to attempt to decode
 * and emulate an instruction that depends on 4GB segments. At this point
 * we assume that the instruction itself is paged into memory (the CPU
 * must have triggered this in order to decode the instruction itself).
 */
int gpf_emulate_4gb(struct xen_regs *regs)
{
    struct domain *d = current;
    trap_info_t   *ti;
    struct trap_bounce *tb;
    u8            modrm, mod, reg, rm, decode;
    void         *memreg, *regreg;
    unsigned long offset;
    u8            disp8;
    u32           disp32 = 0;
    u8            *eip;         /* ptr to instruction start */
    u8            *pb, b;       /* ptr into instr. / current instr. byte */
    unsigned int  *pseg = NULL; /* segment for memory operand (NULL=default) */

    /* WARNING: We only work for ring-3 segments. */
    if ( unlikely((regs->cs & 3) != 3) )
    {
        DPRINTK("Taken fault at bad CS %04x\n", regs->cs);
        goto fail;
    }

    if ( !linearise_address((u16)regs->cs, regs->eip, (unsigned long *)&eip) )
    {
        DPRINTK("Cannot linearise %04x:%08lx\n", regs->cs, regs->eip);
        goto fail;
    }

    /* Parse prefix bytes. We're basically looking for segment override. */
    for ( pb = eip; ; pb++ )
    {
        if ( get_user(b, pb) )
        {
            DPRINTK("Fault while accessing byte %d of instruction\n", pb-eip);
            goto fail;
        }

        if ( (pb - eip) == 4 )
            break;
        
        switch ( b )
        {
        case 0xf0: /* LOCK */
        case 0xf2: /* REPNE/REPNZ */
        case 0xf3: /* REP/REPE/REPZ */
        case 0x67: /* Address-size override */
            DPRINTK("Unhandleable prefix byte %02x\n", b);
            goto fixme;
        case 0x66: /* Operand-size override */
            break;
        case 0x2e: /* CS override */
            pseg = &regs->cs;
            break;
        case 0x3e: /* DS override */
            pseg = &regs->ds;
            break;
        case 0x26: /* ES override */
            pseg = &regs->es;
            break;
        case 0x64: /* FS override */
            pseg = &regs->fs;
            break;
        case 0x65: /* GS override */
            pseg = &regs->gs;
            break;
        case 0x36: /* SS override */
            pseg = &regs->ss;
            break;
        default: /* Not a prefix byte */
            goto done_prefix;
        }
    }
 done_prefix:

    decode = insn_decode[b]; /* opcode byte */
    pb++;
    if ( decode == 0 )
    {
        DPRINTK("Unsupported opcode %02x\n", b);
        goto fail;
    }
    
    if ( !(decode & HAS_MODRM) )
    {
        switch ( decode & 7 )
        {
        case 1:
            offset = (long)(*(char *)pb);
            goto skip_modrm;
        case 4:
            offset = *(long *)pb;
            goto skip_modrm;
        default:
            goto fail;
        }
    }

    /*
     * Mod/RM processing.
     */

    if ( get_user(modrm, pb) )
    {
        DPRINTK("Fault while extracting modrm byte\n");
        goto fail;
    }

    pb++;

    mod = (modrm >> 6) & 3;
    reg = (modrm >> 3) & 7;
    rm  = (modrm >> 0) & 7;

    if ( rm == 4 )
    {
        DPRINTK("FIXME: Add decoding for the SIB byte.\n");
        goto fixme;
    }

    /* Decode Reg and R/M fields. */
    regreg = decode_reg(regs, reg);
    memreg = decode_reg(regs, rm);

    /* Decode Mod field. */
    switch ( modrm >> 6 )
    {
    case 0:
        if ( pseg == NULL )
            pseg = &regs->ds;
        disp32 = 0;
        if ( rm == 5 ) /* disp32 rather than (EBP) */
        {
            memreg = NULL;
            if ( get_user(disp32, (u32 *)pb) )
            {
                DPRINTK("Fault while extracting <disp8>.\n");
                goto fail;
            }
            pb += 4;
        }
        break;

    case 1:
        if ( pseg == NULL ) /* NB. EBP defaults to SS */
            pseg = (rm == 5) ? &regs->ss : &regs->ds;
        if ( get_user(disp8, pb) )
        {
            DPRINTK("Fault while extracting <disp8>.\n");
            goto fail;
        }
        pb++;
        disp32 = (disp8 & 0x80) ? (disp8 | ~0xff) : disp8;;
        break;

    case 2:
        if ( pseg == NULL ) /* NB. EBP defaults to SS */
            pseg = (rm == 5) ? &regs->ss : &regs->ds;
        if ( get_user(disp32, (u32 *)pb) )
        {
            DPRINTK("Fault while extracting <disp8>.\n");
            goto fail;
        }
        pb += 4;
        break;

    case 3:
        DPRINTK("Not a memory operand!\n");
        goto fail;
    }

    offset = disp32;
    if ( memreg != NULL )
        offset += *(u32 *)memreg;

 skip_modrm:
    if ( !fixup_seg((u16)(*pseg), (signed long)offset >= 0) )
        goto fail;

    /* Success! */
    perfc_incrc(seg_fixups);

    /* If requested, give a callback on otherwise unused vector 15. */
    if ( VM_ASSIST(d, VMASST_TYPE_4gb_segments_notify) )
    {
        ti  = &d->thread.traps[15];
        tb = &d->thread.trap_bounce;
        tb->flags      = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
        tb->error_code = pb - eip;
        tb->cs         = ti->cs;
        tb->eip        = ti->address;
        if ( TI_GET_IF(ti) )
            d->shared_info->vcpu_data[0].evtchn_upcall_mask = 1;
    }

    return 1;

 fixme:
    DPRINTK("Undecodable instruction %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
            "caused GPF(0) at %04x:%08lx\n",
            eip[0], eip[1], eip[2], eip[3],
            eip[4], eip[5], eip[6], eip[7],
            regs->cs, regs->eip);
 fail:
    return 0;
}
