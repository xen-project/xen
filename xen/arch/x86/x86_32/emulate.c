/******************************************************************************
 * arch/x86/x86_32/emulate.c
 * 
 * Emulation of certain classes of IA32 instruction. Used to emulate 4GB
 * segments, for example.
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

void *decode_reg(struct pt_regs *regs, u8 b)
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
 * Decode an effective address:
 *  @ppb (IN/OUT): IN == address of ModR/M byte; OUT == byte following EA.
 *  @preg (OUT)  : address in pt_regs block of the EA register parameter.
 *  @pmem (OUT)  : address of the EA memory parameter.
 *  @pseg (IN)   : address in pt_regs block of the override segment.
 *  @regs (IN)   : addrress of the the pt_regs block.
 */
int decode_effective_address(u8 **ppb, void **preg, void **pmem,
                             unsigned int *pseg, struct pt_regs *regs)
{
    u8            modrm, mod, reg, rm, *pb = *ppb;
    void         *memreg, *regreg;
    unsigned long ea, limit, offset;
    u8            disp8;
    u32           disp32 = 0;

    if ( get_user(modrm, pb) )
    {
        DPRINTK("Fault while extracting modrm byte\n");
        return 0;
    }

    pb++;

    mod = (modrm >> 6) & 3;
    reg = (modrm >> 3) & 7;
    rm  = (modrm >> 0) & 7;

    if ( rm == 4 )
    {
        DPRINTK("FIXME: Add decoding for the SIB byte.\n");
        return 0;
    }

    /* Decode Reg and R/M fields. */
    regreg = decode_reg(regs, reg);
    memreg = decode_reg(regs, rm);

    /* Decode Mod field. */
    switch ( modrm >> 6 )
    {
    case 0:
        if ( pseg == NULL )
            pseg = &regs->xds;
        disp32 = 0;
        if ( rm == 5 ) /* disp32 rather than (EBP) */
        {
            memreg = NULL;
            if ( get_user(disp32, (u32 *)pb) )
            {
                DPRINTK("Fault while extracting <disp8>.\n");
                return 0;
            }
            pb += 4;
        }
        break;

    case 1:
        if ( pseg == NULL ) /* NB. EBP defaults to SS */
            pseg = (rm == 5) ? &regs->xss : &regs->xds;
        if ( get_user(disp8, pb) )
        {
            DPRINTK("Fault while extracting <disp8>.\n");
            return 0;
        }
        pb++;
        disp32 = (disp8 & 0x80) ? (disp8 | ~0xff) : disp8;;
        break;

    case 2:
        if ( pseg == NULL ) /* NB. EBP defaults to SS */
            pseg = (rm == 5) ? &regs->xss : &regs->xds;
        if ( get_user(disp32, (u32 *)pb) )
        {
            DPRINTK("Fault while extracting <disp8>.\n");
            return 0;
        }
        pb += 4;
        break;

    case 3:
        DPRINTK("Not a memory operand!\n");
        return 0;
    }

    if ( !get_baselimit((u16)(*pseg), &ea, &limit) )
        return 0;
    if ( limit != 0 )
    {
        DPRINTK("Bailing: not a 4GB data segment.\n");
        return 0;
    }

    offset = disp32;
    if ( memreg != NULL )
        offset += *(u32 *)memreg;
    if ( (offset & 0xf0000000) != 0xf0000000 )
    {
        DPRINTK("Bailing: not a -ve offset into 4GB segment.\n");
        return 0;
    }

    ea += offset;
    if ( ea > (PAGE_OFFSET - PAGE_SIZE) )
    {
        DPRINTK("!!!! DISALLOWING UNSAFE ACCESS !!!!\n");
        return 0;
    }

    *ppb  = pb;
    *preg = regreg;
    *pmem = (void *)ea;

    return 1;
}

/*
 * Called from the general-protection fault handler to attempt to decode
 * and emulate an instruction that depends on 4GB segments. At this point
 * we assume that the instruction itself is paged into memory (the CPU
 * must have triggered this in order to decode the instruction itself).
 */
int gpf_emulate_4gb(struct pt_regs *regs)
{
    struct domain *d = current;
    trap_info_t   *ti;
    u8            *eip, *nextbyte, b, mb, rb;
    u16            mw, rw;
    u32            ml, rl, eflags;
    unsigned int  *pseg = NULL;
    int            i;
    int            opsz_override = 0;
    void          *reg, *mem;
    struct guest_trap_bounce *gtb;

    if ( !linearise_address((u16)regs->xcs, regs->eip, (unsigned long *)&eip) )
    {
        DPRINTK("Cannot linearise %04x:%08lx\n", regs->xcs, regs->eip);
        return 0;
    }

    /* Parse prefix bytes. We're basically looking for segment override. */
    for ( i = 0; i < 4; i++ )
    {
        if ( get_user(b, &eip[i]) )
        {
            DPRINTK("Fault while accessing byte %d of instruction\n", i);
            return 0;
        }
        
        switch ( b )
        {
        case 0xf0: /* LOCK */
        case 0xf2: /* REPNE/REPNZ */
        case 0xf3: /* REP/REPE/REPZ */
        case 0x67: /* Address-size override */
            DPRINTK("Unhandleable prefix byte %02x\n", b);
            goto undecodeable;
        case 0x66: /* Operand-size override */
            opsz_override = 1;
            break;
        case 0x2e: /* CS override */
            pseg = &regs->xcs;
            break;
        case 0x3e: /* DS override */
            pseg = &regs->xds;
            break;
        case 0x26: /* ES override */
            pseg = &regs->xes;
            break;
        case 0x64: /* FS override */
            pseg = &regs->xfs;
            break;
        case 0x65: /* GS override */
            pseg = &regs->xgs;
            break;
        case 0x36: /* SS override */
            pseg = &regs->xss;
            break;
        default: /* Not a prefix byte */
            goto done_prefix;
        }
    }
 done_prefix:

    nextbyte = &eip[i+1];
    if ( !decode_effective_address(&nextbyte, &reg, &mem, pseg, regs) )
        goto undecodeable;

    /* Only handle single-byte opcodes right now. Sufficient for MOV. */
    /*
     * XXX Now I see how this decode routine is panning out, it needs
     * refactoring. Lots of duplicated cruft in here...
     */
    switch ( b )
    {
    case 0x88: /* movb r,r/m */
        if ( __put_user(*(u8 *)reg, (u8 *)mem) )
            goto page_fault_w;
        regs->eip += nextbyte - eip;
        break;
    case 0x89: /* movl r,r/m */
        if ( opsz_override )
        {
            if ( __put_user(*(u16 *)reg, (u16 *)mem) )
                goto page_fault_w;
        }
        else
        {
            if ( __put_user(*(u32 *)reg, (u32 *)mem) )
                goto page_fault_w;
        }
        regs->eip += nextbyte - eip;
        break;
    case 0x8a: /* movb r/m,r */
        if ( __get_user(*(u8 *)reg, (u8 *)mem) )
            goto page_fault_r;
        regs->eip += nextbyte - eip;
        break;
    case 0x8b: /* movl r/m,r */
        if ( opsz_override )
        {
            if ( __get_user(*(u16 *)reg, (u16 *)mem) )
                goto page_fault_r;
        }
        else
        {
            if ( __get_user(*(u32 *)reg, (u32 *)mem) )
                goto page_fault_r;
        }
        regs->eip += nextbyte - eip;
        break;
    case 0xc6: /* movb imm,r/m */
        if ( reg != &regs->eax ) /* Reg == /0 */
            goto undecodeable;
        if ( get_user(rb, nextbyte) )
        {
            DPRINTK("Fault while extracting immediate byte\n");
            return 0;
        }
        if ( __put_user(rb, (u8 *)mem) )
            goto page_fault_w;
        regs->eip += nextbyte - eip + 1;
        break;
    case 0xc7: /* movl imm,r/m */
        if ( reg != &regs->eax ) /* Reg == /0 */
            goto undecodeable;
        if ( opsz_override )
        {
            if ( get_user(rw, (u16 *)nextbyte) )
            {
                DPRINTK("Fault while extracting immediate word\n");
                return 0;
            }
            if ( __put_user(rw, (u16 *)mem) )
                goto page_fault_w;
            regs->eip += nextbyte - eip + 2;
        }
        else
        {
            if ( get_user(rl, (u32 *)nextbyte) )
            {
                DPRINTK("Fault while extracting immediate longword\n");
                return 0;
            }
            if ( __put_user(rl, (u32 *)mem) )
                goto page_fault_w;
            regs->eip += nextbyte - eip + 4;
        }
        break;
    case 0x80: /* cmpb imm8,r/m */
        if ( reg != &regs->edi ) /* Reg == /7 */
            goto undecodeable;
        if ( get_user(rb, nextbyte) )
        {
            DPRINTK("Fault while extracting immediate byte\n");
            return 0;
        }
        if ( __get_user(mb, (u8 *)mem) )
            goto page_fault_r;
        __asm__ __volatile__ (
            "cmpb %b1,%b2 ; pushf ; popl %0"
            : "=a" (eflags)
            : "0" (rb), "b" (mb) );
        regs->eflags &= ~0x8d5;     /* OF,SF,ZF,AF,PF,CF */
        regs->eflags |= eflags & 0x8d5;
        regs->eip += nextbyte - eip + 1;
        break;
    case 0x81: /* cmpl imm32,r/m */
        if ( reg != &regs->edi ) /* Reg == /7 */
            goto undecodeable;
        if ( opsz_override )
        {
            if ( get_user(rw, (u16 *)nextbyte) )
            {
                DPRINTK("Fault while extracting immediate word\n");
                return 0;
            }
            if ( __get_user(mw, (u16 *)mem) )
                goto page_fault_r;
            __asm__ __volatile__ (
                "cmpw %w1,%w2 ; pushf ; popl %0"
                : "=a" (eflags)
                : "0" (rw), "b" (mw) );
            regs->eip += nextbyte - eip + 2;
        }
        else
        {
            if ( get_user(rl, (u32 *)nextbyte) )
            {
                DPRINTK("Fault while extracting immediate longword\n");
                return 0;
            }
            if ( __get_user(ml, (u32 *)mem) )
                goto page_fault_r;
            __asm__ __volatile__ (
                "cmpl %1,%2 ; pushf ; popl %0"
                : "=a" (eflags)
                : "0" (rl), "b" (ml) );
            regs->eip += nextbyte - eip + 4;
        }
        regs->eflags &= ~0x8d5;     /* OF,SF,ZF,AF,PF,CF */
        regs->eflags |= eflags & 0x8d5;
        break;
    case 0x83: /* cmpl imm8,r/m */
        if ( reg != &regs->edi ) /* Reg == /7 */
            goto undecodeable;
        if ( get_user(rb, nextbyte) )
        {
            DPRINTK("Fault while extracting immediate byte\n");
            return 0;
        }
        if ( opsz_override )
        {
            rw = (rb & 0x80) ? (rb | ~0xff) : rb;
            if ( __get_user(mw, (u16 *)mem) )
                goto page_fault_r;
            __asm__ __volatile__ (
                "cmpw %w1,%w2 ; pushf ; popl %0"
                : "=a" (eflags)
                : "0" (rw), "b" (mw) );
            regs->eip += nextbyte - eip + 2;
        }
        else
        {
            rl = (rb & 0x80) ? (rb | ~0xff) : rb;
            if ( __get_user(ml, (u32 *)mem) )
                goto page_fault_r;
            __asm__ __volatile__ (
                "cmpl %1,%2 ; pushf ; popl %0"
                : "=a" (eflags)
                : "0" (rl), "b" (ml) );
        }
        regs->eflags &= ~0x8d5;     /* OF,SF,ZF,AF,PF,CF */
        regs->eflags |= eflags & 0x8d5;
        regs->eip += nextbyte - eip + 1;
        break;
    case 0x38: /* cmpb r,r/m */
    case 0x3a: /* cmpb r/m,r */
        rb = *(u8 *)reg;
        if ( __get_user(mb, (u8 *)mem) )
            goto page_fault_r;
        __asm__ __volatile__ (
            "cmpb %b1,%b2 ; pushf ; popl %0"
            : "=a" (eflags)
            : "0" ((b==0x38)?rb:mb), "b" ((b==0x38)?mb:rb) );
        regs->eflags &= ~0x8d5;     /* OF,SF,ZF,AF,PF,CF */
        regs->eflags |= eflags & 0x8d5;
        regs->eip += nextbyte - eip;
        break;
    case 0x39: /* cmpl r,r/m */
    case 0x3b: /* cmpl r/m,r */
        if ( opsz_override )
        {
            rw = *(u16 *)reg;
            if ( __get_user(mw, (u16 *)mem) )
                goto page_fault_r;
            __asm__ __volatile__ (
                "cmpw %w1,%w2 ; pushf ; popl %0"
                : "=a" (eflags)
                : "0" ((b==0x38)?rw:mw), "b" ((b==0x38)?mw:rw) );
        }
        else
        {
            rl = *(u32 *)reg;
            if ( __get_user(ml, (u32 *)mem) )
                goto page_fault_r;
            __asm__ __volatile__ (
                "cmpl %1,%2 ; pushf ; popl %0"
                : "=a" (eflags)
                : "0" ((b==0x38)?rl:ml), "b" ((b==0x38)?ml:rl) );
        }
        regs->eflags &= ~0x8d5;     /* OF,SF,ZF,AF,PF,CF */
        regs->eflags |= eflags & 0x8d5;
        regs->eip += nextbyte - eip;
        break;
    default:
        DPRINTK("Unhandleable opcode byte %02x\n", b);
        goto undecodeable;
    }

    perfc_incrc(emulations);

    /* Success! */
    return 1;

 undecodeable:
    printk("Undecodable instruction %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
           "caused GPF(0) at %04x:%08lx\n",
           eip[0], eip[1], eip[2], eip[3],
           eip[4], eip[5], eip[6], eip[7],
           regs->xcs, regs->eip);
    return 0;

 page_fault_w:
    ti  = &d->thread.traps[14];
    gtb = &guest_trap_bounce[d->processor];
    /*
     * XXX We don't distinguish between page-not-present and read-only.
     * Linux doesn't care, but this might need fixing if others do.
     */
    gtb->error_code = 6; /* user fault, write access, page not present */
    goto page_fault_common;
 page_fault_r:
    ti  = &d->thread.traps[14];
    gtb = &guest_trap_bounce[d->processor];
    gtb->error_code = 4; /* user fault, read access, page not present */
 page_fault_common:
    gtb->flags      = GTBF_TRAP_CR2;
    gtb->cr2        = (unsigned long)mem;
    gtb->cs         = ti->cs;
    gtb->eip        = ti->address;
    if ( TI_GET_IF(ti) )
        d->shared_info->vcpu_data[0].evtchn_upcall_mask = 1;
    return 1;
}


