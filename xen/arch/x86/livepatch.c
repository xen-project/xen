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
#include <xen/sched.h>
#include <xen/vm_event.h>
#include <xen/virtual_region.h>

#include <asm/endbr.h>
#include <asm/fixmap.h>
#include <asm/nmi.h>
#include <asm/livepatch.h>
#include <asm/setup.h>

static bool has_active_waitqueue(const struct vm_event_domain *ved)
{
    /* ved may be xzalloc()'d without INIT_LIST_HEAD() yet. */
    return (ved && !list_head_is_null(&ved->wq.list) &&
            !list_empty(&ved->wq.list));
}

/*
 * x86's implementation of waitqueue violates the livepatching safety principle
 * of having unwound every CPUs stack before modifying live content.
 *
 * Search through every domain and check that no vCPUs have an active
 * waitqueue.
 */
int arch_livepatch_safety_check(void)
{
    struct domain *d;

    for_each_domain ( d )
    {
#ifdef CONFIG_MEM_SHARING
        if ( has_active_waitqueue(d->vm_event_share) )
            goto fail;
#endif
#ifdef CONFIG_MEM_PAGING
        if ( has_active_waitqueue(d->vm_event_paging) )
            goto fail;
#endif
        if ( has_active_waitqueue(d->vm_event_monitor) )
            goto fail;
    }

    return 0;

 fail:
    printk(XENLOG_ERR LIVEPATCH "%pd found with active waitqueue\n", d);
    return -EBUSY;
}

int noinline arch_livepatch_quiesce(void)
{
    /*
     * Relax perms on .text/.rodata, so we can modify them.
     *
     * This relaxes perms globally, but all other CPUs are waiting on us.
     */
    relax_virtual_region_perms();
    flush_local(FLUSH_TLB_GLOBAL);

    return 0;
}

void noinline arch_livepatch_revive(void)
{
    /*
     * Reinstate perms on .text/.rodata.  This also cleans out the dirty
     * bits, which matters when CET Shstk is active.
     *
     * The other CPUs waiting for us could in principle have re-walked while
     * we were patching and cached the reduced perms in their TLB.  Therefore,
     * we need to do a global TLB flush.
     *
     * However, we can't use Xen's normal global TLB flush infrastructure, so
     * delay the TLB flush to arch_livepatch_post_action(), which is called on
     * all CPUs (including us) on the way out of patching.
     */
    tighten_virtual_region_perms();
}

int arch_livepatch_verify_func(const struct livepatch_func *func)
{
    /* If NOPing.. */
    if ( !func->new_addr )
    {
        /* Only do up to maximum amount we can put in the ->opaque. */
        if ( func->new_size > LIVEPATCH_OPAQUE_SIZE )
            return -EOPNOTSUPP;

        if ( func->old_size < func->new_size )
            return -EINVAL;
    }
    else
    {
        /*
         * Space needed now depends on whether the target function
         * start{s,ed} with an ENDBR64 instruction.
         */
        uint8_t needed = ARCH_PATCH_INSN_SIZE;

        if ( is_endbr64(func->old_addr) || is_endbr64_poison(func->old_addr) )
            needed += ENDBR64_LEN;

        if ( func->old_size < needed )
            return -EINVAL;
    }

    return 0;
}

/*
 * "noinline" to cause control flow change and thus invalidate I$ and
 * cause refetch after modification.
 */
void noinline arch_livepatch_apply(const struct livepatch_func *func,
                                   struct livepatch_fstate *state)
{
    uint8_t *old_ptr;
    uint8_t insn[sizeof(state->insn_buffer)];
    unsigned int len;

    state->patch_offset = 0;
    old_ptr = func->old_addr;

    /*
     * CET hotpatching support: We may have functions starting with an ENDBR64
     * instruction that MUST remain the first instruction of the function,
     * hence we need to move any hotpatch trampoline further into the function.
     * For that we need to keep track of the patching offset used for any
     * loaded hotpatch (to avoid racing against other fixups adding/removing
     * ENDBR64 or similar instructions).
     */
    if ( is_endbr64(old_ptr) || is_endbr64_poison(func->old_addr) )
        state->patch_offset += ENDBR64_LEN;

    /* This call must be done with ->patch_offset already set. */
    len = livepatch_insn_len(func, state);
    if ( !len )
        return;

    memcpy(state->insn_buffer, old_ptr + state->patch_offset, len);
    if ( func->new_addr )
    {
        int32_t val;

        BUILD_BUG_ON(ARCH_PATCH_INSN_SIZE != (1 + sizeof(val)));

        insn[0] = 0xe9; /* Relative jump. */
        val = func->new_addr - (func->old_addr + state->patch_offset +
                                ARCH_PATCH_INSN_SIZE);

        memcpy(&insn[1], &val, sizeof(val));
    }
    else
        add_nops(insn, len);

    memcpy(old_ptr + state->patch_offset, insn, len);
}

/*
 * "noinline" to cause control flow change and thus invalidate I$ and
 * cause refetch after modification.
 */
void noinline arch_livepatch_revert(const struct livepatch_func *func,
                                    struct livepatch_fstate *state)
{
    memcpy(func->old_addr + state->patch_offset, state->insn_buffer,
           livepatch_insn_len(func, state));
}

/*
 * "noinline" to cause control flow change and thus invalidate I$ and
 * cause refetch after modification.
 */
void noinline arch_livepatch_post_action(void)
{
    /* See arch_livepatch_revive() */
    flush_local(FLUSH_TLB_GLOBAL);
}

static nmi_callback_t *saved_nmi_callback;
/*
 * Note that because of this NOP code the do_nmi is not safely patchable.
 * Also if we do receive 'real' NMIs we have lost them.
 */
static int cf_check mask_nmi_callback(const struct cpu_user_regs *regs, int cpu)
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
        printk(XENLOG_ERR LIVEPATCH "%s: Unsupported ELF Machine type\n",
               elf->name);
        return -EOPNOTSUPP;
    }

    return 0;
}

bool arch_livepatch_symbol_ok(const struct livepatch_elf *elf,
                              const struct livepatch_elf_sym *sym)
{
    /* No special checks on x86. */
    return true;
}

bool arch_livepatch_symbol_deny(const struct livepatch_elf *elf,
                                const struct livepatch_elf_sym *sym)
{
    /* No special checks on x86. */
    return false;
}

int arch_livepatch_perform_rel(struct livepatch_elf *elf,
                               const struct livepatch_elf_sec *base,
                               const struct livepatch_elf_sec *rela)
{
    printk(XENLOG_ERR LIVEPATCH "%s: SHT_REL relocation unsupported\n",
           elf->name);
    return -EOPNOTSUPP;
}

int arch_livepatch_perform_rela(struct livepatch_elf *elf,
                                const struct livepatch_elf_sec *base,
                                const struct livepatch_elf_sec *rela)
{
    unsigned int i;

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        const Elf_RelA *r = rela->addr + i * rela->sec->sh_entsize;
        unsigned int symndx = ELF64_R_SYM(r->r_info);
        uint8_t *dest = base->addr + r->r_offset;
        uint64_t val;

        if ( symndx == STN_UNDEF )
        {
            printk(XENLOG_ERR LIVEPATCH "%s: Encountered STN_UNDEF\n",
                   elf->name);
            return -EOPNOTSUPP;
        }
        else if ( symndx >= elf->nsym )
        {
            printk(XENLOG_ERR LIVEPATCH "%s: Relative relocation wants symbol@%u which is past end\n",
                   elf->name, symndx);
            return -EINVAL;
        }
        else if ( !elf->sym[symndx].sym )
        {
            printk(XENLOG_ERR LIVEPATCH "%s: No symbol@%u\n",
                   elf->name, symndx);
            return -EINVAL;
        }
        else if ( elf->sym[symndx].ignored )
        {
            printk(XENLOG_ERR LIVEPATCH
                   "%s: Relocation against ignored symbol %s cannot be resolved\n",
                   elf->name, elf->sym[symndx].name);
            return -EINVAL;
        }

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
                printk(XENLOG_ERR LIVEPATCH "%s: Overflow in relocation %u in %s for %s\n",
                       elf->name, i, rela->name, base->name);
                return -EOVERFLOW;
            }
            break;

        default:
            printk(XENLOG_ERR LIVEPATCH "%s: Unhandled relocation %lu\n",
                   elf->name, ELF64_R_TYPE(r->r_info));
            return -EOPNOTSUPP;
        }
    }

    return 0;

 bad_offset:
    printk(XENLOG_ERR LIVEPATCH "%s: Relative relocation offset is past %s section\n",
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

    return modify_xen_mappings(start, start + pages * PAGE_SIZE, flag);
}

void __init arch_livepatch_init(void)
{
    void *start, *end;

    start = (void *)__2M_rwdata_end;
    end = (void *)(XEN_VIRT_END - FIXADDR_X_SIZE - NR_CPUS * PAGE_SIZE);

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
