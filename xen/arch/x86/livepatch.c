/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/vmap.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>

#include <asm/nmi.h>

#define PATCH_INSN_SIZE 5

void arch_livepatch_quiesce(void)
{
    /* Disable WP to allow changes to read-only pages. */
    write_cr0(read_cr0() & ~X86_CR0_WP);
}

void arch_livepatch_revive(void)
{
    /* Reinstate WP. */
    write_cr0(read_cr0() | X86_CR0_WP);
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    /* No NOP patching yet. */
    if ( !func->new_size )
        return -EOPNOTSUPP;

    if ( func->old_size < PATCH_INSN_SIZE )
        return -EINVAL;

    return 0;
}

void arch_livepatch_apply_jmp(struct livepatch_func *func)
{
    int32_t val;
    uint8_t *old_ptr;

    BUILD_BUG_ON(PATCH_INSN_SIZE > sizeof(func->opaque));
    BUILD_BUG_ON(PATCH_INSN_SIZE != (1 + sizeof(val)));

    old_ptr = func->old_addr;
    memcpy(func->opaque, old_ptr, PATCH_INSN_SIZE);

    *old_ptr++ = 0xe9; /* Relative jump */
    val = func->new_addr - func->old_addr - PATCH_INSN_SIZE;
    memcpy(old_ptr, &val, sizeof(val));
}

void arch_livepatch_revert_jmp(const struct livepatch_func *func)
{
    memcpy(func->old_addr, func->opaque, PATCH_INSN_SIZE);
}

/* Serialise the CPU pipeline. */
void arch_livepatch_post_action(void)
{
    cpuid_eax(0);
}

static nmi_callback_t *saved_nmi_callback;
/*
 * Note that because of this NOP code the do_nmi is not safely patchable.
 * Also if we do receive 'real' NMIs we have lost them.
 */
static int mask_nmi_callback(const struct cpu_user_regs *regs, int cpu)
{
    /* TODO: Handle missing NMI/MCE.*/
    return 1;
}

void arch_livepatch_mask(void)
{
    saved_nmi_callback = set_nmi_callback(mask_nmi_callback);
}

void arch_livepatch_unmask(void)
{
    set_nmi_callback(saved_nmi_callback);
}

int arch_livepatch_verify_elf(const struct livepatch_elf *elf)
{

    const Elf_Ehdr *hdr = elf->hdr;

    if ( hdr->e_machine != EM_X86_64 ||
         hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
         hdr->e_ident[EI_DATA] != ELFDATA2LSB )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Unsupported ELF Machine type!\n",
                elf->name);
        return -EOPNOTSUPP;
    }

    return 0;
}

int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    dprintk(XENLOG_ERR, LIVEPATCH "%s: SHT_REL relocation unsupported\n",
            elf->name);
    return -EOPNOTSUPP;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    const Elf_RelA *r;
    unsigned int symndx, i;
    uint64_t val;
    uint8_t *dest;

    /* Nothing to do. */
    if ( !rela->sec->sh_size )
        return 0;

    if ( rela->sec->sh_entsize < sizeof(Elf_RelA) ||
         rela->sec->sh_size % rela->sec->sh_entsize )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Section relative header is corrupted!\n",
                elf->name);
        return -EINVAL;
    }

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        r = rela->data + i * rela->sec->sh_entsize;

        symndx = ELF64_R_SYM(r->r_info);

        if ( symndx > elf->nsym )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative relocation wants symbol@%u which is past end!\n",
                    elf->name, symndx);
            return -EINVAL;
        }

        dest = base->load_addr + r->r_offset;
        val = r->r_addend + elf->sym[symndx].sym->st_value;

        switch ( ELF64_R_TYPE(r->r_info) )
        {
        case R_X86_64_NONE:
            break;

        case R_X86_64_64:
            if ( r->r_offset >= base->sec->sh_size ||
                (r->r_offset + sizeof(uint64_t)) > base->sec->sh_size )
                goto bad_offset;

            *(uint64_t *)dest = val;
            break;

        case R_X86_64_PLT32:
            /*
             * Xen uses -fpic which normally uses PLT relocations
             * except that it sets visibility to hidden which means
             * that they are not used.  However, when gcc cannot
             * inline memcpy it emits memcpy with default visibility
             * which then creates a PLT relocation.  It can just be
             * treated the same as R_X86_64_PC32.
             */
        case R_X86_64_PC32:
            if ( r->r_offset >= base->sec->sh_size ||
                (r->r_offset + sizeof(uint32_t)) > base->sec->sh_size )
                goto bad_offset;

            val -= (uint64_t)dest;
            *(int32_t *)dest = val;
            if ( (int64_t)val != *(int32_t *)dest )
            {
                dprintk(XENLOG_ERR, LIVEPATCH "%s: Overflow in relocation %u in %s for %s!\n",
                        elf->name, i, rela->name, base->name);
                return -EOVERFLOW;
            }
            break;

        default:
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Unhandled relocation %lu\n",
                    elf->name, ELF64_R_TYPE(r->r_info));
            return -EOPNOTSUPP;
        }
    }

    return 0;

 bad_offset:
    dprintk(XENLOG_ERR, LIVEPATCH "%s: Relative relocation offset is past %s section!\n",
            elf->name, base->name);
    return -EINVAL;
}

/*
 * Once the resolving symbols, performing relocations, etc is complete
 * we secure the memory by putting in the proper page table attributes
 * for the desired type.
 */
int arch_livepatch_secure(const void *va, unsigned int pages, enum va_type type)
{
    unsigned long start = (unsigned long)va;
    unsigned int flag;

    ASSERT(va);
    ASSERT(pages);

    if ( type == LIVEPATCH_VA_RX )
        flag = PAGE_HYPERVISOR_RX;
    else if ( type == LIVEPATCH_VA_RW )
        flag = PAGE_HYPERVISOR_RW;
    else
        flag = PAGE_HYPERVISOR_RO;

    modify_xen_mappings(start, start + pages * PAGE_SIZE, flag);

    return 0;
}

void __init arch_livepatch_init(void)
{
    void *start, *end;

    start = (void *)xen_virt_end;
    end = (void *)(XEN_VIRT_END - NR_CPUS * PAGE_SIZE);

    BUG_ON(end <= start);

    vm_init_type(VMAP_XEN, start, end);
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
