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
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/mman.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>

#if 1
#define ASSERT(_p) \
    if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s", #_p , \
    __LINE__, __FILE__); *(int*)0=0; }
#define DPRINTK(_f, _a...) printk(KERN_ALERT \
                           "(file=%s, line=%d) " _f "\n", \
                           __FILE__ , __LINE__ , ## _a )
#else
#define ASSERT(_p) ((void)0)
#define DPRINTK(_f, _a...) ((void)0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define TestSetPageLocked(_p) TryLockPage(_p)
#define PageAnon(_p)          0 /* no equivalent in 2.4 */
#define pte_offset_kernel     pte_offset
#define remap_page_range(_a,_b,_c,_d,_e) remap_page_range(_b,_c,_d,_e)
#define daemonize(_n)                   \
    do {                                \
        daemonize();                    \
        strcpy(current->comm, _n);      \
        sigfillset(&current->blocked);  \
    } while ( 0 )
#endif

static unsigned char *fixup_buf;
#define FIXUP_BUF_USER  PAGE_SIZE
#define FIXUP_BUF_ORDER 1
#define FIXUP_BUF_SIZE  (PAGE_SIZE<<FIXUP_BUF_ORDER)
#define PATCH_LEN       5

struct fixup_entry {
    unsigned char  patched_code[20];
    unsigned short patched_code_len;
    unsigned short fixup_idx;
    unsigned short return_idx;
    struct fixup_entry *next;
};

#define FIXUP_HASHSZ 128
static struct fixup_entry *fixup_hash[FIXUP_HASHSZ];
static inline int FIXUP_HASH(char *b)
{
    int i, j = 0;
    for ( i = 0; i < PATCH_LEN; i++ )
        j ^= b[i];
    return j & (FIXUP_HASHSZ-1);
}

/* General instruction properties. */
#define INSN_SUFFIX_BYTES (7)
#define PREFIX_BYTE       (1<<3)
#define OPCODE_BYTE       (1<<4)  
#define HAS_MODRM         (1<<5)

/* Helpful codes for the main decode routine. */
#define CODE_MASK         (3<<6)
#define PUSH              (1<<6) /* PUSH onto stack */
#define POP               (2<<6) /* POP from stack */
#define JMP               (3<<6) /* 8-bit relative JMP */

/* Short forms for the table. */
#define X  0 /* invalid for some random reason */
#define S  0 /* invalid because it munges the stack */
#define P  PREFIX_BYTE
#define O  OPCODE_BYTE
#define M  HAS_MODRM

static unsigned char insn_decode[256] = {
    /* 0x00 - 0x0F */
    O|M, O|M, O|M, O|M, O|1, O|4, S, S,
    O|M, O|M, O|M, O|M, O|1, O|4, S, X,
    /* 0x10 - 0x1F */
    O|M, O|M, O|M, O|M, O|1, O|4, S, S,
    O|M, O|M, O|M, O|M, O|1, O|4, S, S,
    /* 0x20 - 0x2F */
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    /* 0x30 - 0x3F */
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    O|M, O|M, O|M, O|M, O|1, O|4, P, O,
    /* 0x40 - 0x4F */
    O, O, O, O, S, O, O, O,
    O, O, O, O, S, O, O, O,
    /* 0x50 - 0x5F */
    O|PUSH, O|PUSH, O|PUSH, O|PUSH, S, O|PUSH, O|PUSH, O|PUSH,
    O|POP, O|POP, O|POP, O|POP, S, O|POP, O|POP, O|POP,
    /* 0x60 - 0x6F */
    S, S, O|M, O|M, P, P, X, X,
    O|4|PUSH, O|M|4, O|1|PUSH, O|M|1, O, O, O, O,
    /* 0x70 - 0x7F */
    O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP,
    O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP, O|1|JMP,
    /* 0x80 - 0x8F */
    O|M|1, O|M|4, O|M|1, O|M|1, O|M, O|M, O|M, O|M,
    O|M, O|M, O|M, O|M, O|M, O|M, O|M, O|M|POP, 
    /* 0x90 - 0x9F */
    O, O, O, O, S, O, O, O,
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
    X, O|4, X, O|1|JMP, X, X, X, X,
    /* 0xF0 - 0xFF */
    P, X, P, P, O, O, O|M|1, O|M|4, 
    O, O, O, O, O, O, O|M, X
};

/* Bitmap of faulting instructions that we can handle. */
static unsigned char handleable_code[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x80-0x83, 0x89, 0x8B */
    0x0F, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0xC7 */
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Bitmap of opcodes that use a register operand specified by Mod/RM. */
static unsigned char opcode_uses_reg[32] = {
    /* 0x00 - 0x3F */
    0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    /* 0x40 - 0x7F */
    0x00, 0x00, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00,
    /* 0x80 - 0xBF */
    0xF0, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0xC0 - 0xFF */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned int parse_insn(unsigned char *insn, 
                               unsigned char *p_opcode,
                               unsigned char *p_decode)
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
    *p_decode = d;

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

    /* 4. All done. Result is all bytes stepped over, plus any immediates. */
    return ((pb - insn) + 1 + (d & INSN_SUFFIX_BYTES));
}

#define SUCCESS 1
#define FAIL    0
static int map_fixup_buf(struct mm_struct *mm)
{
    struct vm_area_struct *vma;

    /* Already mapped? This is a pretty safe check. */
    if ( ((vma = find_vma(current->mm, FIXUP_BUF_USER)) != NULL) &&
         (vma->vm_start <= FIXUP_BUF_USER) &&
         (vma->vm_flags == (VM_READ | VM_MAYREAD | VM_RESERVED)) &&
         (vma->vm_file == NULL) )
        return SUCCESS;

    if ( (vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL)) == NULL )
    {
        DPRINTK("Cannot allocate VMA.");
        return FAIL;
    }

    memset(vma, 0, sizeof(*vma));

    vma->vm_mm        = mm;
    vma->vm_flags     = VM_READ | VM_MAYREAD | VM_RESERVED;
    vma->vm_page_prot = PAGE_READONLY;

    down_write(&mm->mmap_sem);

    vma->vm_start = get_unmapped_area(
        NULL, FIXUP_BUF_USER, FIXUP_BUF_SIZE,
        0, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED);
    if ( vma->vm_start != FIXUP_BUF_USER )
    {
        DPRINTK("Cannot allocate low-memory-region VMA.");
        up_write(&mm->mmap_sem);
        kmem_cache_free(vm_area_cachep, vma);
        return FAIL;
    }

    vma->vm_end = vma->vm_start + FIXUP_BUF_SIZE;

    if ( remap_page_range(vma, vma->vm_start, __pa(fixup_buf), 
                          vma->vm_end - vma->vm_start, vma->vm_page_prot) )
    {
        DPRINTK("Cannot map low-memory-region VMA.");
        up_write(&mm->mmap_sem);
        kmem_cache_free(vm_area_cachep, vma);
        return FAIL;
    }

    insert_vm_struct(mm, vma);
    
    mm->total_vm += FIXUP_BUF_SIZE >> PAGE_SHIFT;

    up_write(&mm->mmap_sem);

    return SUCCESS;
}

/*
 * Mainly this function checks that our patches can't erroneously get flushed
 * to a file on disc, which would screw us after reboot!
 */
#define SUCCESS 1
#define FAIL    0
static int safe_to_patch(struct mm_struct *mm, unsigned long addr)
{
    struct vm_area_struct *vma;
    struct file           *file;
    unsigned char          _name[30], *name;

    /* Always safe to patch the fixup buffer. */
    if ( addr <= (FIXUP_BUF_USER + FIXUP_BUF_SIZE) )
        return SUCCESS;

    if ( ((vma = find_vma(current->mm, addr)) == NULL) ||
         (vma->vm_start > addr) )
    {
        DPRINTK("No VMA contains fault address.");
        return FAIL;
    }

    /* Only patch shared libraries. */
    if ( (file = vma->vm_file) == NULL )
    {
        DPRINTK("VMA is anonymous!");
        return FAIL;
    }

    /* No shared mappings => nobody can dirty the file. */
    /* XXX Note the assumption that noone will dirty the file in future! */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    if ( file->f_mapping->i_mmap_writable != 0 )
#else
    if ( file->f_dentry->d_inode->i_mapping->i_mmap_shared != NULL )
#endif
    {
        DPRINTK("Shared mappings exist.");
        return FAIL;
    }

    /*
     * Because of above dodgy assumption, we will only patch things in
     * /lib/tls. Our belief is that updates here will only ever occur by
     * unlinking the old files and installing completely fresh ones. :-)
     */
    name = d_path(file->f_dentry, file->f_vfsmnt, _name, sizeof(_name));
    if ( IS_ERR(name) || (strncmp("/lib/tls", name, 8) != 0) )
    {
        DPRINTK("Backing file is not in /lib/tls");
        return FAIL;
    }

    return SUCCESS;
}

asmlinkage void do_fixup_4gb_segment(struct pt_regs *regs, long error_code)
{
    static unsigned int fixup_idx = 0;
    struct mm_struct *mm = current->mm;
    unsigned int fi;
    int save_indirect_reg, hash, i;
    unsigned int insn_len = (unsigned int)error_code, new_insn_len;
    unsigned char b[20], modrm, mod, reg, rm, sib, patch[20], opcode, decode;
    unsigned long eip = regs->eip - insn_len;
    struct fixup_entry *fe;
    struct page *page;
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

    if ( unlikely(!map_fixup_buf(mm)) )
        goto out;

    /* Hold the mmap_sem to prevent the mapping from disappearing under us. */
    down_read(&mm->mmap_sem);

    if ( unlikely(!safe_to_patch(mm, eip)) )
        goto out;

    if ( unlikely(copy_from_user(b, (void *)eip, sizeof(b)) != 0) )
    {
        DPRINTK("Could not read instruction bytes from user space.");
        goto out;
    }

    /* Already created a fixup for this code sequence? */
    hash = FIXUP_HASH(b);
    for ( fe = fixup_hash[hash]; fe != NULL; fe = fe->next )
    {
        if ( memcmp(fe->patched_code, b, fe->patched_code_len) == 0 )
            goto do_the_patch;
    }

    /* Guaranteed enough room to patch? */
    if ( unlikely((fi = fixup_idx) > (FIXUP_BUF_SIZE-64)) )
    {
        static int printed = 0;
        if ( !printed )
            printk(KERN_ALERT "WARNING: Out of room in segment-fixup page.\n");
        printed = 1;
        goto out;
    }

    /* Must be a handleable opcode with GS override. */
    if ( (b[0] != 0x65) || 
         !test_bit((unsigned int)b[1], (unsigned long *)handleable_code) )
    {
        DPRINTK("No GS override, or not a MOV (%02x %02x).", b[0], b[1]);
        goto out;
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
        goto out;
    }

    /* Ensure Mod/RM specifies (r32) or disp8(r32). */
    switch ( mod )
    {
    case 0:
        if ( rm == 5 )
        {
            DPRINTK("Unhandleable disp32 EA %d.", rm);
            goto out;
        }
        break;            /* m32 == (r32) */
    case 1:
        break;            /* m32 == disp8(r32) */
    default:
        DPRINTK("Unhandleable Mod value %d.", mod);
        goto out;
    }

    /* Indirect jump pointer. */
    *(u32 *)&fixup_buf[fi] = FIXUP_BUF_USER + fi + 4;
    fi += 4;

    /* push <r32> */
    if ( save_indirect_reg )
        fixup_buf[fi++] = 0x50 + rm;

    /* pushf */
    fixup_buf[fi++] = 0x9c;

    /* add %gs:0,<r32> */
    fixup_buf[fi++] = 0x65;
    fixup_buf[fi++] = 0x03;
    fixup_buf[fi++] = 0x05 | (rm << 3);
    *(unsigned long *)&fixup_buf[fi] = 0;
    fi += 4;

    /* popf */
    fixup_buf[fi++] = 0x9d;

    /* Relocate the faulting instruction, minus the GS override. */
    memcpy(&fixup_buf[fi], &b[1], error_code - 1);
    fi += error_code - 1;

    /* pop <r32> */
    if ( save_indirect_reg )
        fixup_buf[fi++] = 0x58 + rm;

    for ( ; ; )
    {
        if ( insn_len >= PATCH_LEN )
        {
            /* ret */
            fixup_buf[fi++] = 0xc3;
            break;
        }

        /* Bail if can't decode the following instruction. */
        if ( unlikely((new_insn_len =
                       parse_insn(&b[insn_len], &opcode, &decode)) == 0) )
        {
            DPRINTK("Could not decode following instruction.");
            goto out;
        }

        if ( (decode & CODE_MASK) == JMP )
        {
            long off;

            memcpy(&fixup_buf[fi], &b[insn_len], new_insn_len - 1);
            fi += new_insn_len - 1;
            
            /* Patch the 8-bit relative offset. */
            fixup_buf[fi++] = 1;
            
            insn_len += new_insn_len;
            ASSERT(insn_len >= PATCH_LEN);
        
            /* ret */
            fixup_buf[fi++] = 0xc3;

            /* pushf */
            fixup_buf[fi++] = 0x9c;

            off = (insn_len - PATCH_LEN) + (long)(char)b[insn_len-1];
            if ( unlikely(off > 127) )
            {
                /* add <imm32>,4(%esp) */
                fixup_buf[fi++] = 0x81;
                fixup_buf[fi++] = 0x44;
                fixup_buf[fi++] = 0x24;
                fixup_buf[fi++] = 0x04;
                fi += 4;
                *(long *)&fixup_buf[fi-4] = off;
            }
            else
            {
                /* add <imm8>,4(%esp) [sign-extended] */
                fixup_buf[fi++] = 0x83;
                fixup_buf[fi++] = 0x44;
                fixup_buf[fi++] = 0x24;
                fixup_buf[fi++] = 0x04;
                fixup_buf[fi++] = (char)(off & 0xff);
            }

            /* popf */
            fixup_buf[fi++] = 0x9d;

            /* ret */
            fixup_buf[fi++] = 0xc3;

            break;
        }
        else if ( opcode == 0xe9 ) /* jmp <rel32> */
        {
            insn_len += new_insn_len;
            ASSERT(insn_len >= PATCH_LEN);
        
            /* pushf */
            fixup_buf[fi++] = 0x9c;

            /* add <imm32>,4(%esp) */
            fixup_buf[fi++] = 0x81;
            fixup_buf[fi++] = 0x44;
            fixup_buf[fi++] = 0x24;
            fixup_buf[fi++] = 0x04;
            fi += 4;
            *(long *)&fixup_buf[fi-4] = 
                (insn_len - PATCH_LEN) + *(long *)&b[insn_len-4];

            /* popf */
            fixup_buf[fi++] = 0x9d;

            /* ret */
            fixup_buf[fi++] = 0xc3;

            break;
        }
        else if ( opcode == 0xc3 ) /* ret */
        {
            /* pop -4(%esp) [doesn't affect EFLAGS] */
            fixup_buf[fi++] = 0x8f;
            fixup_buf[fi++] = 0x44;
            fixup_buf[fi++] = 0x24;
            fixup_buf[fi++] = 0xfc;
        }
        else
        {
            int stack_addon = 4;

            if ( (decode & CODE_MASK) == PUSH )
            {
                stack_addon = 8;
                /* push (%esp) */
                fixup_buf[fi++] = 0xff;
                fixup_buf[fi++] = 0x34;
                fixup_buf[fi++] = 0x24;
            }
            else if ( (decode & CODE_MASK) == POP )
            {
                stack_addon = 8;
                /* push 4(%esp) */
                fixup_buf[fi++] = 0xff;
                fixup_buf[fi++] = 0x74;
                fixup_buf[fi++] = 0x24;
                fixup_buf[fi++] = 0x04;
            }

            /* Check for EA calculations involving ESP, and skip return addr */
            if ( decode & HAS_MODRM )
            {
                do { new_insn_len--; }
                while ( (fixup_buf[fi++] = b[insn_len++]) != opcode );

                modrm = fixup_buf[fi++] = b[insn_len++];
                new_insn_len--;
                mod   = (modrm >> 6) & 3;
                reg   = (modrm >> 3) & 7;
                rm    = (modrm >> 0) & 7;

                if ( (reg == 4) &&
                     test_bit(opcode, (unsigned long *)opcode_uses_reg) )
                {
                    DPRINTK("Data movement to ESP unsupported.");
                    goto out;
                }

                if ( rm == 4 )
                {
                    if ( mod == 3 )
                    {
                        DPRINTK("Data movement to ESP is unsupported.");
                        goto out;
                    }

                    sib = fixup_buf[fi++] = b[insn_len++];
                    new_insn_len--;
                    if ( (sib & 7) == 4 )
                    {
                        switch ( mod )
                        {
                        case 0:
                            mod = 1;
                            fixup_buf[fi-2] |= 0x40;
                            fixup_buf[fi++] = stack_addon;
                            break;
                        case 1:
                            fixup_buf[fi++] = b[insn_len++] + stack_addon;
                            new_insn_len--;
                            break;
                        case 2:
                            *(long *)&fixup_buf[fi] = 
                                *(long *)&b[insn_len] + stack_addon;
                            fi += 4;
                            insn_len += 4;
                            new_insn_len -= 4;
                            break;
                        }
                    }
                }
            }

            /* Relocate the (remainder of) the instruction. */
            if ( new_insn_len != 0 )
            {
                memcpy(&fixup_buf[fi], &b[insn_len], new_insn_len);
                fi += new_insn_len;
            }

            if ( (decode & CODE_MASK) == PUSH )
            {
                /* pop 4(%esp) */
                fixup_buf[fi++] = 0x8f;
                fixup_buf[fi++] = 0x44;
                fixup_buf[fi++] = 0x24;
                fixup_buf[fi++] = 0x04;
            }
            else if ( (decode & CODE_MASK) == POP )
            {
                /* pop (%esp) */
                fixup_buf[fi++] = 0x8f;
                fixup_buf[fi++] = 0x04;
                fixup_buf[fi++] = 0x24;
            }
        }

        if ( (insn_len += new_insn_len) > 20 )
        {
            DPRINTK("Code to patch is too long!");
            goto out;
        }

        /* Can't have a RET in the middle of a patch sequence. */
        if ( (opcode == 0xc3) && (insn_len < PATCH_LEN) )
        {
            DPRINTK("RET in middle of patch seq!\n");
            goto out;
        }
    }

    /* Create an entry for a new fixup patch. */
    fe = kmalloc(sizeof(struct fixup_entry), GFP_KERNEL);
    if ( unlikely(fe == NULL) )
    {
        DPRINTK("Not enough memory to allocate a fixup_entry.");
        goto out;
    }
    fe->patched_code_len = insn_len;
    memcpy(fe->patched_code, b, insn_len);
    fe->fixup_idx = fixup_idx;
    fe->return_idx = 
        fixup_idx + error_code + (save_indirect_reg ? 14 : 12);
    fe->next = fixup_hash[hash];
    fixup_hash[hash] = fe;

    /* Commit the patch. */
    fixup_idx = fi;

 do_the_patch:

    if ( unlikely(((eip ^ (eip + fe->patched_code_len)) & PAGE_MASK) != 0) )
    {
        DPRINTK("Patch instruction would straddle a page boundary.");
        goto out;
    }

    if ( put_user(eip + PATCH_LEN, (unsigned long *)regs->esp - 1) != 0 )
    {
        DPRINTK("Failed to place return address on user stack.");
        goto out;
    }

    /* Create the patching instructions in a temporary buffer. */
    patch[0] = 0x67;
    patch[1] = 0xff;
    patch[2] = 0x16; /* call <r/m16> */
    *(u16 *)&patch[3] = FIXUP_BUF_USER + fe->fixup_idx;
    for ( i = 5; i < fe->patched_code_len; i++ )
        patch[i] = 0x90; /* nop */

    spin_lock(&mm->page_table_lock);

    /* Find the physical page that is to be patched. */
    pgd = pgd_offset(current->mm, eip);
    if ( unlikely(!pgd_present(*pgd)) )
        goto unlock_and_out;
    pmd = pmd_offset(pgd, eip);
    if ( unlikely(!pmd_present(*pmd)) )
        goto unlock_and_out;
    pte = pte_offset_kernel(pmd, eip);
    if ( unlikely(!pte_present(*pte)) )
        goto unlock_and_out;
    page = pte_page(*pte);

    /*
     * We get lock to prevent page going AWOL on us. Also a locked page
     * might be getting flushed to disc!
     */
    if ( unlikely(TestSetPageLocked(page)) )
    {
        DPRINTK("Page is locked.");
        goto unlock_and_out;
    }

    /*
     * If page is dirty it will get flushed back to disc - bad news! An
     * anonymous page may be moulinexed under our feet by another thread.
     */
    if ( unlikely(PageDirty(page)) || unlikely(PageAnon(page)) )
    {
        DPRINTK("Page is dirty or anonymous.");
        unlock_page(page);
        goto unlock_and_out;
    }

    veip = kmap(page);
    memcpy((char *)veip + (eip & ~PAGE_MASK), patch, fe->patched_code_len);
    kunmap(page);

    unlock_page(page);
    spin_unlock(&mm->page_table_lock);

    /* Success! Return to user land to execute 2nd insn of the pair. */
    regs->esp -= 4;
    regs->eip = FIXUP_BUF_USER + fe->return_idx;

 out:
    up_read(&mm->mmap_sem);
    return;

 unlock_and_out:
    spin_unlock(&mm->page_table_lock);
    up_read(&mm->mmap_sem);
    return;
}

static int fixup_thread(void *unused)
{
    daemonize("segfixup");
    
    for ( ; ; )
    {
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
    }
}

static int nosegfixup = 0;

static int __init fixup_init(void)
{
    int i;

    nosegfixup = 1; /* XXX */

    if ( !nosegfixup )
    {
        HYPERVISOR_vm_assist(VMASST_CMD_enable,
                             VMASST_TYPE_4gb_segments_notify);
        fixup_buf = (char *)__get_free_pages(GFP_ATOMIC, FIXUP_BUF_ORDER);
        for ( i = 0; i < (1 << FIXUP_BUF_ORDER); i++ )
            SetPageReserved(virt_to_page(fixup_buf) + i);
        memset(fixup_hash, 0, sizeof(fixup_hash));
        (void)kernel_thread(fixup_thread, NULL, CLONE_FS | CLONE_FILES);
    }

    return 0;
}
__initcall(fixup_init);

static int __init fixup_setup(char *str)
{
    nosegfixup = 1;
    return 0;
}
__setup("nosegfixup", fixup_setup);
