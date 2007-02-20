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
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/regs.h>
#include <asm/x86_emulate.h>

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
    O|4, O|4, O|4, O|4, X, X, X, X,
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
    struct vcpu *d = current;
    unsigned long *table, a, b;
    int            ldt = !!(seg & 4);
    int            idx = (seg >> 3) & 8191;

    /* Get base and check limit. */
    if ( ldt )
    {
        table = (unsigned long *)LDT_VIRT_START(d);
        if ( idx >= d->arch.guest_context.ldt_ents )
            goto fail;
    }
    else /* gdt */
    {
        table = (unsigned long *)GDT_VIRT_START(d);
        if ( idx >= d->arch.guest_context.gdt_ents )
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
    if ( (GUEST_SEGMENT_MAX_ADDR - (*base + *limit)) < PAGE_SIZE )
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

int fixup_seg(u16 seg, unsigned long offset)
{
    struct vcpu *d = current;
    unsigned long *table, a, b, base, limit;
    int            ldt = !!(seg & 4);
    int            idx = (seg >> 3) & 8191;

    /* Get base and check limit. */
    if ( ldt )
    {
        table = (unsigned long *)LDT_VIRT_START(d);
        if ( idx >= d->arch.guest_context.ldt_ents )
        {
            dprintk(XENLOG_DEBUG, "Segment %04x out of LDT range (%ld)\n",
                    seg, d->arch.guest_context.ldt_ents);
            goto fail;
        }
    }
    else /* gdt */
    {
        table = (unsigned long *)GDT_VIRT_START(d);
        if ( idx >= d->arch.guest_context.gdt_ents )
        {
            dprintk(XENLOG_DEBUG, "Segment %04x out of GDT range (%ld)\n",
                    seg, d->arch.guest_context.gdt_ents);
            goto fail;
        }
    }

    /* Grab the segment descriptor. */
    if ( __get_user(a, &table[2*idx+0]) ||
         __get_user(b, &table[2*idx+1]) )
    {
        dprintk(XENLOG_DEBUG, "Fault while reading segment %04x\n", seg);
        goto fail; /* Barking up the wrong tree. Decode needs a page fault.*/
    }

    /* We only parse 32-bit page-granularity non-privileged data segments. */
    if ( (b & (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|
               _SEGMENT_G|_SEGMENT_CODE|_SEGMENT_DPL)) != 
         (_SEGMENT_P|_SEGMENT_S|_SEGMENT_DB|_SEGMENT_G|_SEGMENT_DPL) )
    {
        dprintk(XENLOG_DEBUG, "Bad segment %08lx:%08lx\n", a, b);
        goto fail;
    }

    /* Decode base and limit. */
    base  = (b&(0xff<<24)) | ((b&0xff)<<16) | (a>>16);
    limit = (((b & 0xf0000) | (a & 0x0ffff)) + 1) << 12;

    if ( b & _SEGMENT_EC )
    {
        /* Expands-down: All the way to zero? Assume 4GB if so. */
        if ( ((base + limit) < PAGE_SIZE) && (offset <= limit)  )
        {
            /* Flip to expands-up. */
            limit = GUEST_SEGMENT_MAX_ADDR - base;
            goto flip;
        }
    }
    else
    {
        /* Expands-up: All the way to Xen space? Assume 4GB if so. */
        if ( ((GUEST_SEGMENT_MAX_ADDR - (base + limit)) < PAGE_SIZE) &&
             (offset > limit) )
        {
            /* Flip to expands-down. */
            limit = -(base & PAGE_MASK);
            goto flip;
        }
    }

    dprintk(XENLOG_DEBUG, "None of the above! "
            "(%08lx:%08lx, %08lx, %08lx, %08lx)\n",
            a, b, base, limit, base+limit);

 fail:
    return 0;

 flip:
    limit = (limit >> 12) - 1;
    a &= ~0x0ffff; a |= limit & 0x0ffff;
    b &= ~0xf0000; b |= limit & 0xf0000;
    b ^= _SEGMENT_EC; /* grows-up <-> grows-down */
    /* NB. These can't fault. Checked readable above; must also be writable. */
    table[2*idx+0] = a;
    table[2*idx+1] = b;
    return 1;
}

/*
 * Called from the general-protection fault handler to attempt to decode
 * and emulate an instruction that depends on 4GB segments.
 */
int gpf_emulate_4gb(struct cpu_user_regs *regs)
{
    struct vcpu *d = current;
    struct trap_info   *ti;
    struct trap_bounce *tb;
    u8            modrm, mod, reg, rm, decode;
    void         *memreg;
    unsigned long offset;
    u8            disp8;
    u32           disp32 = 0;
    u8            *eip;         /* ptr to instruction start */
    u8            *pb, b;       /* ptr into instr. / current instr. byte */
    int            gs_override = 0;

    /* WARNING: We only work for ring-3 segments. */
    if ( unlikely(vm86_mode(regs)) || unlikely(!ring_3(regs)) )
        goto fail;

    if ( !linearise_address((u16)regs->cs, regs->eip, (unsigned long *)&eip) )
    {
        dprintk(XENLOG_DEBUG, "Cannot linearise %04x:%08x\n",
                regs->cs, regs->eip);
        goto fail;
    }

    /* Parse prefix bytes. We're basically looking for segment override. */
    for ( pb = eip; ; pb++ )
    {
        if ( get_user(b, pb) )
        {
            dprintk(XENLOG_DEBUG,
                    "Fault while accessing byte %ld of instruction\n",
                    (long)(pb-eip));
            goto page_fault;
        }

        if ( (pb - eip) >= 15 )
        {
            dprintk(XENLOG_DEBUG, "Too many instruction prefixes for a "
                    "legal instruction\n");
            goto fail;
        }

        switch ( b )
        {
        case 0x67: /* Address-size override */
        case 0x2e: /* CS override */
        case 0x3e: /* DS override */
        case 0x26: /* ES override */
        case 0x64: /* FS override */
        case 0x36: /* SS override */
            dprintk(XENLOG_DEBUG, "Unhandled prefix %02x\n", b);
            goto fail;
        case 0x66: /* Operand-size override */
        case 0xf0: /* LOCK */
        case 0xf2: /* REPNE/REPNZ */
        case 0xf3: /* REP/REPE/REPZ */
            break;
        case 0x65: /* GS override */
            gs_override = 1;
            break;
        default: /* Not a prefix byte */
            goto done_prefix;
        }
    }
 done_prefix:

    if ( !gs_override )
    {
        dprintk(XENLOG_DEBUG, "Only instructions with GS override\n");
        goto fail;
    }

    decode = insn_decode[b]; /* opcode byte */
    pb++;
    if ( decode == 0 )
    {
        dprintk(XENLOG_DEBUG, "Unsupported opcode %02x\n", b);
        goto fail;
    }
    
    if ( !(decode & HAS_MODRM) )
    {
        /* Must be a <disp32>, or bail. */
        if ( (decode & 7) != 4 )
            goto fail;

        if ( get_user(offset, (u32 *)pb) )
        {
            dprintk(XENLOG_DEBUG, "Fault while extracting <disp32>.\n");
            goto page_fault;
        }
        pb += 4;

        goto skip_modrm;
    }

    /*
     * Mod/RM processing.
     */

    if ( get_user(modrm, pb) )
    {
        dprintk(XENLOG_DEBUG, "Fault while extracting modrm byte\n");
        goto page_fault;
    }

    pb++;

    mod = (modrm >> 6) & 3;
    reg = (modrm >> 3) & 7;
    rm  = (modrm >> 0) & 7;

    if ( rm == 4 )
    {
        dprintk(XENLOG_DEBUG, "FIXME: Add decoding for the SIB byte.\n");
        goto fixme;
    }

    /* Decode R/M field. */
    memreg = decode_register(rm,  regs, 0);

    /* Decode Mod field. */
    switch ( modrm >> 6 )
    {
    case 0:
        disp32 = 0;
        if ( rm == 5 ) /* disp32 rather than (EBP) */
        {
            memreg = NULL;
            if ( get_user(disp32, (u32 *)pb) )
            {
                dprintk(XENLOG_DEBUG, "Fault while extracting <disp8>.\n");
                goto page_fault;
            }
            pb += 4;
        }
        break;

    case 1:
        if ( get_user(disp8, pb) )
        {
            dprintk(XENLOG_DEBUG, "Fault while extracting <disp8>.\n");
            goto page_fault;
        }
        pb++;
        disp32 = (disp8 & 0x80) ? (disp8 | ~0xff) : disp8;;
        break;

    case 2:
        if ( get_user(disp32, (u32 *)pb) )
        {
            dprintk(XENLOG_DEBUG, "Fault while extracting <disp8>.\n");
            goto page_fault;
        }
        pb += 4;
        break;

    case 3:
        dprintk(XENLOG_DEBUG, "Not a memory operand!\n");
        goto fail;
    }

    offset = disp32;
    if ( memreg != NULL )
        offset += *(u32 *)memreg;

 skip_modrm:
    if ( !fixup_seg((u16)regs->gs, offset) )
        goto fail;

    /* Success! */
    perfc_incrc(seg_fixups);

    /* If requested, give a callback on otherwise unused vector 15. */
    if ( VM_ASSIST(d->domain, VMASST_TYPE_4gb_segments_notify) )
    {
        ti  = &d->arch.guest_context.trap_ctxt[15];
        tb  = &d->arch.trap_bounce;
        tb->flags      = TBF_EXCEPTION | TBF_EXCEPTION_ERRCODE;
        tb->error_code = pb - eip;
        tb->cs         = ti->cs;
        tb->eip        = ti->address;
        if ( TI_GET_IF(ti) )
            tb->flags |= TBF_INTERRUPT;
    }

    return EXCRET_fault_fixed;

 fixme:
    dprintk(XENLOG_DEBUG, "Undecodable instruction "
            "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
            "caused GPF(0) at %04x:%08x\n",
            eip[0], eip[1], eip[2], eip[3],
            eip[4], eip[5], eip[6], eip[7],
            regs->cs, regs->eip);
 fail:
    return 0;

 page_fault:
    propagate_page_fault((unsigned long)pb, 0); /* read fault */
    return EXCRET_fault_fixed;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
