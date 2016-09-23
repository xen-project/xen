/*
 *  Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#include <xen/bitops.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/mm.h>
#include <xen/vmap.h>

#include <asm/bitops.h>
#include <asm/byteorder.h>
#include <asm/insn.h>
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
        insn = aarch64_insn_gen_branch_imm((unsigned long)func->old_addr,
                                           (unsigned long)func->new_addr,
                                           AARCH64_INSN_BRANCH_NOLINK);
    else
        insn = aarch64_insn_gen_nop();

    /* Verified in livepatch_verify_distance. */
    ASSERT(insn != AARCH64_BREAK_FAULT);

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

    if ( hdr->e_machine != EM_AARCH64 ||
         hdr->e_ident[EI_CLASS] != ELFCLASS64 )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    return 0;
}

bool arch_livepatch_symbol_deny(const struct livepatch_elf *elf,
                                const struct livepatch_elf_sym *sym)
{
    /* No special checks on ARM 64. */
    return false;
}

enum aarch64_reloc_op {
    RELOC_OP_NONE,
    RELOC_OP_ABS,
    RELOC_OP_PREL,
    RELOC_OP_PAGE,
};

static u64 do_reloc(enum aarch64_reloc_op reloc_op, void *place, u64 val)
{
    switch ( reloc_op )
    {
    case RELOC_OP_ABS:
        return val;

    case RELOC_OP_PREL:
        return val - (u64)place;

    case RELOC_OP_PAGE:
        return (val & ~0xfff) - ((u64)place & ~0xfff);

    case RELOC_OP_NONE:
        return 0;

    }

    dprintk(XENLOG_DEBUG, LIVEPATCH "do_reloc: unknown relocation operation %d\n", reloc_op);

    return 0;
}

static int reloc_data(enum aarch64_reloc_op op, void *place, u64 val, int len)
{
    s64 sval = do_reloc(op, place, val);

    switch ( len )
    {
    case 16:
        *(s16 *)place = sval;
        if ( sval < INT16_MIN || sval > UINT16_MAX )
	        return -EOVERFLOW;
        break;

    case 32:
        *(s32 *)place = sval;
        if ( sval < INT32_MIN || sval > UINT32_MAX )
	        return -EOVERFLOW;
        break;

    case 64:
        *(s64 *)place = sval;
        break;

    default:
        dprintk(XENLOG_DEBUG, LIVEPATCH "Invalid length (%d) for data relocation\n", len);
        return 0;
    }

    return 0;
}

enum aarch64_insn_movw_imm_type {
    AARCH64_INSN_IMM_MOVNZ,
    AARCH64_INSN_IMM_MOVKZ,
};

static int reloc_insn_movw(enum aarch64_reloc_op op, void *dest, u64 val,
                           int lsb, enum aarch64_insn_movw_imm_type imm_type)
{
    u64 imm;
    s64 sval;
    u32 insn = *(u32 *)dest;

    sval = do_reloc(op, dest, val);
    imm = sval >> lsb;

    if ( imm_type == AARCH64_INSN_IMM_MOVNZ )
    {
        /*
         * For signed MOVW relocations, we have to manipulate the
         * instruction encoding depending on whether or not the
         * immediate is less than zero.
         */
        insn &= ~(3 << 29);
        if ( sval >= 0 )
        {
            /* >=0: Set the instruction to MOVZ (opcode 10b). */
            insn |= 2 << 29;
        }
        else
        {
            /*
             * <0: Set the instruction to MOVN (opcode 00b).
             *     Since we've masked the opcode already, we
             *     don't need to do anything other than
             *     inverting the new immediate field.
             */
            imm = ~imm;
        }
    }

    /* Update the instruction with the new encoding. */
    insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn, imm);
    *(u32 *)dest = insn;

    if ( imm > UINT16_MAX )
        return -EOVERFLOW;

    return 0;
}

static int reloc_insn_imm(enum aarch64_reloc_op op, void *dest, u64 val,
                          int lsb, int len, enum aarch64_insn_imm_type imm_type)
{
    u64 imm, imm_mask;
    s64 sval;
    u32 insn = *(u32 *)dest;

    /* Calculate the relocation value. */
    sval = do_reloc(op, dest, val);
    sval >>= lsb;

    /* Extract the value bits and shift them to bit 0. */
    imm_mask = (BIT(lsb + len) - 1) >> lsb;
    imm = sval & imm_mask;

    /* Update the instruction's immediate field. */
    insn = aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)dest = insn;

    /*
     * Extract the upper value bits (including the sign bit) and
     * shift them to bit 0.
     */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

    /*
     * Overflow has occurred if the upper bits are not all equal to
     * the sign bit of the value.
     */
    if ( (u64)(sval + 1) >= 2 )
        return -EOVERFLOW;
    return 0;
}

int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    return -ENOSYS;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    const Elf_RelA *r;
    unsigned int symndx, i;
    uint64_t val;
    void *dest;
    bool_t overflow_check;

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        int ovf = 0;

        r = rela->data + i * rela->sec->sh_entsize;

        symndx = ELF64_R_SYM(r->r_info);

        if ( symndx > elf->nsym )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative relocation wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        dest = base->load_addr + r->r_offset; /* P */
        val = elf->sym[symndx].sym->st_value +  r->r_addend; /* S+A */

        overflow_check = true;

        /* ARM64 operations at minimum are always 32-bit. */
        if ( r->r_offset >= base->sec->sh_size ||
            (r->r_offset + sizeof(uint32_t)) > base->sec->sh_size )
            goto bad_offset;

        switch ( ELF64_R_TYPE(r->r_info) )
        {
        /* Data */
        case R_AARCH64_ABS64:
            if ( r->r_offset + sizeof(uint64_t) > base->sec->sh_size )
                goto bad_offset;
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_ABS, dest, val, 64);
            break;

        case R_AARCH64_ABS32:
            ovf = reloc_data(RELOC_OP_ABS, dest, val, 32);
            break;

        case R_AARCH64_ABS16:
            ovf = reloc_data(RELOC_OP_ABS, dest, val, 16);
            break;

        case R_AARCH64_PREL64:
            if ( r->r_offset + sizeof(uint64_t) > base->sec->sh_size )
                goto bad_offset;
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_PREL, dest, val, 64);
            break;

        case R_AARCH64_PREL32:
            ovf = reloc_data(RELOC_OP_PREL, dest, val, 32);
            break;

        case R_AARCH64_PREL16:
            ovf = reloc_data(RELOC_OP_PREL, dest, val, 16);
            break;

        /* MOVW instruction relocations. */
        case R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = false;
            /* Fallthrough. */

        case R_AARCH64_MOVW_UABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 0,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = false;
            /* Fallthrough. */

        case R_AARCH64_MOVW_UABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 16,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = false;
            /* Fallthrough. */

        case R_AARCH64_MOVW_UABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 32,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_UABS_G3:
            /* We're using the top bits so we can't overflow. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 48,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_SABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 0,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        case R_AARCH64_MOVW_SABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 16,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        case R_AARCH64_MOVW_SABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, dest, val, 32,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        case R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 0,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_PREL_G0:
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 0,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        case R_AARCH64_MOVW_PREL_G1_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 16,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_PREL_G1:
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 16,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        case R_AARCH64_MOVW_PREL_G2_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 32,
                                  AARCH64_INSN_IMM_MOVKZ);
            break;

        case R_AARCH64_MOVW_PREL_G2:
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 32,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        case R_AARCH64_MOVW_PREL_G3:
            /* We're using the top bits so we can't overflow. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, dest, val, 48,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;

        /* Instructions. */
        case R_AARCH64_ADR_PREL_LO21:
            ovf = reloc_insn_imm(RELOC_OP_PREL, dest, val, 0, 21,
                                 AARCH64_INSN_IMM_ADR);
            break;

        case R_AARCH64_ADR_PREL_PG_HI21_NC:
            overflow_check = false;
        case R_AARCH64_ADR_PREL_PG_HI21:
            ovf = reloc_insn_imm(RELOC_OP_PAGE, dest, val, 12, 21,
                                 AARCH64_INSN_IMM_ADR);
            break;

        case R_AARCH64_LDST8_ABS_LO12_NC:
            /* Fallthrough. */

        case R_AARCH64_ADD_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, dest, val, 0, 12,
                                 AARCH64_INSN_IMM_12);
            break;

        case R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, dest, val, 1, 11,
                                 AARCH64_INSN_IMM_12);
            break;

        case R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, dest, val, 2, 10,
                                 AARCH64_INSN_IMM_12);
            break;

        case R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, dest, val, 3, 9,
                                 AARCH64_INSN_IMM_12);
            break;

        case R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, dest, val, 4, 8,
                                 AARCH64_INSN_IMM_12);
            break;

        case R_AARCH64_TSTBR14:
            ovf = reloc_insn_imm(RELOC_OP_PREL, dest, val, 2, 19,
                                 AARCH64_INSN_IMM_14);
            break;

        case R_AARCH64_CONDBR19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, dest, val, 2, 19,
                                 AARCH64_INSN_IMM_19);
            break;

        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26:
            ovf = reloc_insn_imm(RELOC_OP_PREL, dest, val, 2, 26,
                                 AARCH64_INSN_IMM_26);
            break;

        default:
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Unhandled relocation %lu\n",
                    elf->name, ELF64_R_TYPE(r->r_info));
            return -EOPNOTSUPP;
        }

        if ( overflow_check && ovf == -EOVERFLOW )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Overflow in relocation %u in %s for %s!\n",
                    elf->name, i, rela->name, base->name);
            return ovf;
        }
    }
    return 0;

 bad_offset:
    dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative relocation offset is past %s section!\n",
            elf->name, base->name);
    return -EINVAL;
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
