/******************************************************************************
 * fixup.c
 * 
 * Binary-rewriting of certain IA32 instructions, on notification by Xen.
 * Used to avoid repeated slow emulation of common instructions used by the
 * user-space TLS (Thread-Local Storage) libraries.
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

#include <linux/config.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>

#if 0
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#define DPRINTK(_f, _a...) printk(KERN_ALERT \
                           "(file=%s, line=%d, eip=%08lx) " _f "\n", \
                           __FILE__ , __LINE__ , eip, ## _a )
#else
#define ASSERT(_p) ((void)0)
#define DPRINTK(_f, _a...) ((void)0)
#endif

struct fixup_entry {
    unsigned long  patch_addr;
    unsigned char  patched_code[20];
    unsigned short patched_code_len;
    unsigned short fixup_idx;
    struct fixup_entry *next;
};

#define FIXUP_HASHSZ 128
static struct fixup_entry *fixup_hash[FIXUP_HASHSZ];
#define FIXUP_HASH(_a) ((unsigned int)(_a) & (FIXUP_HASHSZ-1))

#define INSN_SUFFIX_BYTES (7)
#define PREFIX_BYTE       (1<<3)
#define OPCODE_BYTE       (1<<4)  
#define HAS_MODRM         (1<<5)

#define X  0 /* invalid */
#define P  PREFIX_BYTE
#define O  OPCODE_BYTE
#define M  HAS_MODRM

static unsigned char insn_decode[256] = {
    /* 0x00 - 0x0F */
    O|M, O|M, O|M, O|M, O|1, O|4, O, O,
    O|M, O|M, O|M, O|M, O|1, O|4, O, X,
    /* 0x10 - 0x1F */
    O|M, O|M, O|M, O|M, O|1, O|4, O, O,
    O|M, O|M, O|M, O|M, O|1, O|4, O, O,
    /* 0x20 - 0x2F */
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    /* 0x30 - 0x3F */
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    /* 0x40 - 0x4F */
    O, O, O, O, O, O, O, O,
    O, O, O, O, O, O, O, O,
    /* 0x50 - 0x5F */
    O, O, O, O, O, O, O, O,
    O, O, O, O, O, O, O, O,
    /* 0x60 - 0x6F */
    O, O, O|M, O|M, P, P, X, X,
    O|4, O|M|4, O|1, O|M|1, O, O, O, O,
    /* 0x70 - 0x7F */
    O|1, O|1, O|1, O|1, O|1, O|1, O|1, O|1,
    O|1, O|1, O|1, O|1, O|1, O|1, O|1, O|1,
    /* 0x80 - 0x8F */
    O|M|1, O|M|4, O|M|1, O|M|1, O|M, O|M, O|M, O|M,
    O|M, O|M, O|M, O|M, O|M, O|M, O|M, O|M, 
    /* 0x90 - 0x9F */
    O, O, O, O, O, O, O, O,
    O, O, X, O, O, O, O, O,
    /* 0xA0 - 0xAF */
    O|1, O|4, O|1, O|4, O, O, O, O,
    O|1, O|4, O, O, O, O, O, O,
    /* 0xB0 - 0xBF */
    O|1, O|1, O|1, O|1, O|1, O|1, O|1, O|1,
    O|4, O|4, O|4, O|4, O|4, O|4, O|4, O|4,
    /* 0xC0 - 0xCF */
    O|M|1, O|M|1, X, O, X, X, O|M|1, O|M|4,
    X, X, X, X, X, X, X, X,
    /* 0xD0 - 0xDF */
    O|M, O|M, O|M, O|M, O|1, O|1, X, X,
    X, X, X, X, X, X, X, X,
    /* 0xE0 - 0xEF */
    X, X, X, X, X, X, X, X,
    X, O|4, X, O|1, X, X, X, X,
    /* 0xF0 - 0xFF */
    P, X, P, P, O, O, O|M|1, O|M|4, 
    O, O, O, O, O, O, O|M, O|M
};

static unsigned int get_insn_len(unsigned char *insn, unsigned char *p_opcode)
{
    unsigned char b, d, *pb, mod, rm;

    /* 1. Step over the prefix bytes. */
    for ( pb = insn; (pb - insn) < 4; pb++ )
    {
        b = *pb;
        d = insn_decode[b];
        if ( !(d & PREFIX_BYTE) )
            break;
    }

    *p_opcode = b;

    /* 2. Ensure we have a valid opcode byte. */
    if ( !(d & OPCODE_BYTE) )
        return 0;

    /* 3. Process Mod/RM if there is one. */
    if ( d & HAS_MODRM )
    {
        b = *(++pb);
        if ( (mod = (b >> 6) & 3) != 3 )
        {           
            if ( (rm = (b >> 0) & 7) == 4 )
                pb += 1; /* SIB byte */
            switch ( mod )
            {
            case 0:
                if ( rm == 5 )
                    pb += 4; /* disp32 */
                break;
            case 1:
                pb += 1; /* disp8 */
                break;
            case 2:
                pb += 4; /* disp32 */
                break;
            }
        }
    }

    /* 4. All done. Result is all byte sstepped over, plus any immediates. */
    return ((pb - insn) + 1 + (d & INSN_SUFFIX_BYTES));
}

static unsigned char handleable_code[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x80-0x83, 0x89, 0x8B */
    0x0F, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0xC7 */
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

asmlinkage void do_fixup_4gb_segment(struct pt_regs *regs, long error_code)
{
    static unsigned int fixup_idx = 0;
    int relbyte_idx = -1, relword_idx = -1, save_indirect_reg;
    unsigned int insn_len = (unsigned int)error_code, new_insn_len;
    unsigned char b[20], modrm, mod, reg, rm, patch[5], opcode;
    unsigned char *fixup_buf = 
        (unsigned char *)fix_to_virt(FIX_4GB_SEGMENT_FIXUP_RW);
    unsigned long fixup_buf_user = 
        fix_to_virt(FIX_4GB_SEGMENT_FIXUP_RO);
    unsigned long eip = regs->eip - insn_len;
    struct fixup_entry *fe;
    pte_t *pte;
    pmd_t *pmd;
    pgd_t *pgd;
    void *veip;

    /* Easy check that code segment has base 0, max limit. */
    if ( unlikely(regs->xcs != __USER_CS) )
    {
        DPRINTK("Unexpected CS value.");
        return;
    }

    if ( unlikely(eip >= (PAGE_OFFSET-32)) )
    {
        if ( (eip < fixup_buf_user) || (eip >= (fixup_buf_user+PAGE_SIZE-32)) )
        {
            DPRINTK("User executing out of kernel space?!");
            return;
        }
        /* We know it's safe to directly copy teh bytes into our buffer. */
        memcpy(b, (void *)eip, sizeof(b));
    }
    else if ( unlikely(copy_from_user(b, (void *)eip, sizeof(b)) != 0) )
    {
        DPRINTK("Could not read instruction bytes from user space.");
        return;
    }

    if ( unlikely(((eip ^ (eip+5)) & PAGE_MASK) != 0) )
    {
        DPRINTK("Patch instruction would straddle a page boundary.");
        return;
    }

    /* Guaranteed enough room to patch? */
    if ( unlikely(fixup_idx > (PAGE_SIZE-32)) )
    {
        static int printed = 0;
        if ( !printed )
            printk(KERN_ALERT "WARNING: Out of room in segment-fixup page.\n");
        printed = 1;
        return;
    }

    /* Must be a handleable opcode with GS override. */
    if ( (b[0] != 0x65) || 
         !test_bit((unsigned int)b[1], (unsigned long *)handleable_code) )
    {
        DPRINTK("No GS override, or not a MOV (%02x %02x).", b[0], b[1]);
        return;
    }

    modrm = b[2];
    mod   = (modrm >> 6) & 3;
    reg   = (modrm >> 3) & 7;
    rm    = (modrm >> 0) & 7;

    /* If indirect register isn't clobbered then we must push/pop it. */
    save_indirect_reg = !((b[1] == 0x8b) && (reg == rm));

    /* We don't grok SIB bytes. */
    if ( rm == 4 )
    {
        DPRINTK("We don't grok SIB bytes.");
        return;
    }

    /* Ensure Mod/RM specifies (r32) or disp8(r32). */
    switch ( mod )
    {
    case 0:
        if ( rm == 5 )
        {
            DPRINTK("Unhandleable disp32 EA %d.", rm);
            return;
        }
        break;            /* m32 == (r32) */
    case 1:
        break;            /* m32 == disp8(r32) */
    default:
        DPRINTK("Unhandleable Mod value %d.", mod);
        return;
    }

    while ( insn_len < 5 )
    {
        /* Bail if can't decode the following instruction. */
        if ( unlikely((new_insn_len =
                       get_insn_len(&b[insn_len], &opcode)) == 0) )
        {
            DPRINTK("Could not decode following instruction.");
            return;
        }

        /* We track one 8-bit relative offset for patching later. */
        if ( ((opcode >= 0x70) && (opcode <= 0x7f)) || (opcode == 0xeb) )
        {
            if ( relbyte_idx != -1 )
            {
                DPRINTK("Multiple relative offsets in patch seq!");
                return;
            }
            relbyte_idx = insn_len;
            while ( b[relbyte_idx] != opcode )
                relbyte_idx++;
            relbyte_idx++;
        }
        else if ( opcode == 0xe9 )
        {
            if ( relword_idx != -1 )
            {
                DPRINTK("Multiple relative offsets in patch seq!");
                return;
            }
            relword_idx = insn_len;
            while ( b[relword_idx] != opcode )
                relword_idx++;
            relword_idx++;
        }

        if ( (insn_len += new_insn_len) > 20 )
        {
            DPRINTK("Code to patch is too long!");
            return;
        }

        /* The instructions together must be no smaller than 'jmp <disp32>'. */
        if ( insn_len >= 5 )
            break;

        /* Can't have a RET in the middle of a patch sequence. */
        if ( opcode == 0xc4 )
        {
            DPRINTK("RET in middle of patch seq!\n");
            return;
        }
    }

    /* Already created a fixup for this address and code sequence? */
    for ( fe = fixup_hash[FIXUP_HASH(eip)];
          fe != NULL; fe = fe->next )
    {
        if ( (fe->patch_addr == eip) &&
             (fe->patched_code_len == insn_len) &&
             (memcmp(fe->patched_code, b, insn_len) == 0) )
            goto do_the_patch;
    }

    /* No existing patch -- create an entry for one. */
    fe = kmalloc(sizeof(struct fixup_entry), GFP_KERNEL);
    if ( unlikely(fe == NULL) )
    {
        DPRINTK("Not enough memory to allocate a fixup_entry.");
        return;
    }
    fe->patch_addr = eip;
    fe->patched_code_len = insn_len;
    memcpy(fe->patched_code, b, insn_len);
    fe->fixup_idx = fixup_idx;
    fe->next = fixup_hash[FIXUP_HASH(eip)];
    fixup_hash[FIXUP_HASH(eip)] = fe;
    
    /* push <r32> */
    if ( save_indirect_reg )
        fixup_buf[fixup_idx++] = 0x50 + rm;

    /* add %gs:0,<r32> */
    fixup_buf[fixup_idx++] = 0x65;
    fixup_buf[fixup_idx++] = 0x03;
    fixup_buf[fixup_idx++] = 0x05 | (rm << 3);
    *(unsigned long *)&fixup_buf[fixup_idx] = 0;
    fixup_idx += 4;

    /* First relocated instruction, minus the GS override. */
    memcpy(&fixup_buf[fixup_idx], &b[1], error_code - 1);
    fixup_idx += error_code - 1;

    /* pop <r32> */
    if ( save_indirect_reg )
        fixup_buf[fixup_idx++] = 0x58 + rm;

    if ( insn_len != error_code )
    {
        /* Relocated instructions. */
        memcpy(&fixup_buf[fixup_idx], &b[error_code], insn_len - error_code);
        fixup_idx += insn_len - error_code;
    }

    /* jmp <rel32> */
    fixup_buf[fixup_idx++] = 0xe9;
    fixup_idx += 4;
    *(unsigned long *)&fixup_buf[fixup_idx-4] = 
        (eip + insn_len) - (fixup_buf_user + fixup_idx);

    if ( relbyte_idx != -1 )
    {
        /* Patch the 8-bit relative offset. */
        int idx = fe->fixup_idx + relbyte_idx + 6;
        if ( save_indirect_reg )
            idx += 2;
        fixup_buf[idx] = fixup_idx - (idx + 1);
        
        /* jmp <rel32> */
        fixup_buf[fixup_idx++] = 0xe9;
        fixup_idx += 4;
        *(unsigned long *)&fixup_buf[fixup_idx-4] = 
            (eip + relbyte_idx + 1 + (long)(char)b[relbyte_idx]) - 
            (fixup_buf_user + fixup_idx);
    }
    else if ( relword_idx != -1 )
    {
        /* Patch the 32-bit relative offset by subtracting the code disp. */
        int idx = fe->fixup_idx + relword_idx + 6;
        if ( save_indirect_reg )
            idx += 2;
        *(unsigned long *)&fixup_buf[idx] +=
            (eip + relword_idx) - (fixup_buf_user + idx);
    }

 do_the_patch:
    /* Create the patching instruction in a temporary buffer. */
    patch[0] = 0xe9;
    *(unsigned long *)&patch[1] = 
        (fixup_buf_user + fe->fixup_idx) - (eip + 5);

    pgd = pgd_offset(current->mm, eip);
    pmd = pmd_offset(pgd, eip);
    pte = pte_offset_kernel(pmd, eip);
    veip = kmap(pte_page(*pte));
    memcpy((char *)veip + (eip & ~PAGE_MASK), patch, 5);
    kunmap(pte_page(*pte));

    /* Success! Return to user land to execute 2nd insn of the pair. */
    regs->eip = fixup_buf_user + fe->fixup_idx + error_code + 6;
    if ( save_indirect_reg )
        regs->eip += 2;
    return;
}

static int nosegfixup = 0;

static int __init fixup_init(void)
{
    unsigned long page;

    if ( nosegfixup )
        return 0;

    HYPERVISOR_vm_assist(VMASST_CMD_enable,
                         VMASST_TYPE_4gb_segments_notify);

    page = get_zeroed_page(GFP_ATOMIC);
    __set_fixmap(FIX_4GB_SEGMENT_FIXUP_RO, __pa(page), PAGE_READONLY);
    __set_fixmap(FIX_4GB_SEGMENT_FIXUP_RW, __pa(page), PAGE_KERNEL);

    memset(fixup_hash, 0, sizeof(fixup_hash));

    return 0;
}
__initcall(fixup_init);

static int __init fixup_setup(char *str)
{
    nosegfixup = 1;
    return 0;
}
__setup("nosegfixup", fixup_setup);
