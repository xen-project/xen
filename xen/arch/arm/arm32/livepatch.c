/*
 *  Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/errno.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>

#include <asm/page.h>
#include <asm/livepatch.h>

void arch_livepatch_apply(struct livepatch_func *func)
{
    uint32_t insn;
    uint32_t *new_ptr;
    unsigned int i, len;

    BUILD_BUG_ON(ARCH_PATCH_INSN_SIZE > sizeof(func->opaque));
    BUILD_BUG_ON(ARCH_PATCH_INSN_SIZE != sizeof(insn));

    ASSERT(vmap_of_xen_text);

    len = livepatch_insn_len(func);
    if ( !len )
        return;

    /* Save old ones. */
    memcpy(func->opaque, func->old_addr, len);

    if ( func->new_addr )
    {
        s32 delta;

        /*
         * PC is current address (old_addr) + 8 bytes. The semantics for a
         * unconditional branch is to jump to PC + imm32 (offset).
         *
         * ARM DDI 0406C.c, see A2.3 (pg 45) and A8.8.18 pg (pg 334,335)
         *
         */
        delta = (s32)func->new_addr - (s32)(func->old_addr + 8);

        /* The arch_livepatch_symbol_ok should have caught it. */
        ASSERT(delta >= -(s32)ARCH_LIVEPATCH_RANGE ||
               delta < (s32)ARCH_LIVEPATCH_RANGE);

        /* CPU shifts by two (left) when decoding, so we shift right by two. */
        delta = delta >> 2;
        /* Lets not modify the cond. */
        delta &= 0x00FFFFFF;

        insn = 0xea000000 | delta;
    }
    else
        insn = 0xe1a00000; /* mov r0, r0 */

    new_ptr = func->old_addr - (void *)_start + vmap_of_xen_text;
    len = len / sizeof(uint32_t);

    /* PATCH! */
    for ( i = 0; i < len; i++ )
        *(new_ptr + i) = insn;

    /*
    * When we upload the payload, it will go through the data cache
    * (the region is cacheable). Until the data cache is cleaned, the data
    * may not reach the memory. And in the case the data and instruction cache
    * are separated, we may read invalid instruction from the memory because
    * the data cache have not yet synced with the memory. Hence sync it.
    */
    if ( func->new_addr )
        clean_and_invalidate_dcache_va_range(func->new_addr, func->new_size);
    clean_and_invalidate_dcache_va_range(new_ptr, sizeof (*new_ptr) * len);
}

/* arch_livepatch_revert shared with ARM 32/ARM 64. */

int arch_livepatch_verify_elf(const struct livepatch_elf *elf)
{
    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_ARM ||
         hdr->e_ident[EI_CLASS] != ELFCLASS32 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    if ( (hdr->e_flags & EF_ARM_EABI_MASK) != EF_ARM_EABI_VER5 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF EABI(%x)!\n",
                elf->name, hdr->e_flags);
        return -EOPNOTSUPP;
    }

    return 0;
}

bool arch_livepatch_symbol_deny(const struct livepatch_elf *elf,
                                const struct livepatch_elf_sym *sym)
{
    /*
     * Xen does not use Thumb instructions - and we should not see any of
     * them. If we do, abort.
     */
    if ( sym->name && sym->name[0] == '$' && sym->name[1] == 't' )
        return ( !sym->name[2] || sym->name[2] == '.' );

    return false;
}

static s32 get_addend(unsigned char type, void *dest)
{
    s32 addend = 0;

    switch ( type ) {
    case R_ARM_NONE:
        /* ignore */
        break;

    case R_ARM_ABS32:
        addend = *(u32 *)dest;
        break;

    case R_ARM_REL32:
        addend = *(u32 *)dest;
        break;

    case R_ARM_MOVW_ABS_NC:
    case R_ARM_MOVT_ABS:
        addend =  (*(u32 *)dest & 0x00000FFF);
        addend |= (*(u32 *)dest & 0x000F0000) >> 4;
        /* Addend is to sign-extend ([19:16],[11:0]). */
        addend = (s16)addend;
        break;

    case R_ARM_CALL:
    case R_ARM_JUMP24:
        /* Addend = sign_extend (insn[23:0]) << 2 */
        addend = ((*(u32 *)dest & 0xFFFFFF) ^ 0x800000) - 0x800000;
        addend = addend << 2;
        break;
    }

    return addend;
}

static int perform_rel(unsigned char type, void *dest, uint32_t val, s32 addend)
{

    switch ( type ) {
    case R_ARM_NONE:
        /* ignore */
        break;

    case R_ARM_ABS32: /* (S + A) | T */
        *(u32 *)dest = (val + addend);
        break;

    case R_ARM_REL32: /* ((S + A) | T) – P */
        *(u32 *)dest = (val + addend) - (uint32_t)dest;
        break;

    case R_ARM_MOVW_ABS_NC: /* S + A */
    case R_ARM_MOVT_ABS: /* S + A */
        /* Clear addend if needed . */
        if ( addend )
            *(u32 *)dest &= 0xFFF0F000;

        if ( type == R_ARM_MOVT_ABS )
        {
            /*
             * Almost the same as MOVW except it uses the 16 bit
             * high value. Putting it in insn requires shifting right by
             * 16-bit (as we only have 16-bit for imm.
             */
            val &= 0xFFFF0000; /* ResultMask */
            val = val >> 16;
        }
        else
        {
            /* MOVW loads 16 bits into the bottom half of a register. */
            val &= 0xFFFF;
        }
        /* [11:0] = Result_Mask(X) & 0xFFF,[19:16] = Result_Mask(X) >> 12 */
        *(u32 *)dest |= val & 0xFFF;
        *(u32 *)dest |= (val >> 12) << 16;
        break;

    case R_ARM_CALL:
    case R_ARM_JUMP24: /* (S + A) - P */
        /* Clear the old addend. */
        if ( addend )
            *(u32 *)dest &= 0xFF000000;

        val += addend - (uint32_t)dest;

        /*
         * arch_livepatch_verify_distance can't account of addend so we have
         * to do the check here as well.
         */
        if ( (s32)val < -(s32)ARCH_LIVEPATCH_RANGE ||
             (s32)val >= (s32)ARCH_LIVEPATCH_RANGE )
            return -EOVERFLOW;

        /* CPU always shifts insn by two, so complement it. */
        val = val >> 2;
        val &= 0x00FFFFFE;
        *(u32 *)dest |= (uint32_t)val;
        break;

    default:
         return -EOPNOTSUPP;
    }

    return 0;
}

int arch_livepatch_perform(struct livepatch_elf *elf,
                           const struct livepatch_elf_sec *base,
                           const struct livepatch_elf_sec *rela,
                           bool use_rela)
{
    const Elf_RelA *r_a;
    const Elf_Rel *r;
    unsigned int symndx, i;
    uint32_t val;
    void *dest;
    int rc = 0;

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        unsigned char type;
        s32 addend = 0;

        if ( use_rela )
        {
            r_a = rela->data + i * rela->sec->sh_entsize;
            symndx = ELF32_R_SYM(r_a->r_info);
            type = ELF32_R_TYPE(r_a->r_info);
            dest = base->load_addr + r_a->r_offset; /* P */
            addend = r_a->r_addend;
        }
        else
        {
            r = rela->data + i * rela->sec->sh_entsize;
            symndx = ELF32_R_SYM(r->r_info);
            type = ELF32_R_TYPE(r->r_info);
            dest = base->load_addr + r->r_offset; /* P */
        }

        if ( symndx == STN_UNDEF )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Encountered STN_UNDEF\n",
                    elf->name);
            return -EOPNOTSUPP;
        }
        else if ( symndx >= elf->nsym )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative symbol wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }
        else if ( !elf->sym[symndx].sym )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: No relative symbol@%u\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        if ( !use_rela )
            addend = get_addend(type, dest);

        val = elf->sym[symndx].sym->st_value; /* S */

        rc = perform_rel(type, dest, val, addend);
        switch ( rc ) {
        case -EOVERFLOW:
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Overflow in relocation %u in %s for %s!\n",
                    elf->name, i, rela->name, base->name);
            break;

        case -EOPNOTSUPP:
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Unhandled relocation #%x\n",
                    elf->name, type);
            break;

        default:
            break;
        }

        if ( rc )
            break;
    }

    return rc;
}

int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    return arch_livepatch_perform(elf, base, rela, false);
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    return arch_livepatch_perform(elf, base, rela, true);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
