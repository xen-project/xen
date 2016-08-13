/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/cpu.h>
#include <xen/elf.h>
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <xen/lib.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <xen/string.h>
#include <xen/symbols.h>
#include <xen/version.h>
#include <xen/virtual_region.h>
#include <xen/vmap.h>
#include <xen/wait.h>
#include <xen/livepatch_elf.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#include <asm/event.h>

/*
 * Protects against payload_list operations and also allows only one
 * caller in schedule_work.
 */
static DEFINE_SPINLOCK(payload_lock);
static LIST_HEAD(payload_list);

/*
 * Patches which have been applied. Need RCU in case we crash (and then
 * traps code would iterate via applied_list) when adding entries onthe list.
 */
static DEFINE_RCU_READ_LOCK(rcu_applied_lock);
static LIST_HEAD(applied_list);

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

/* To contain the ELF Note header. */
struct livepatch_build_id {
   const void *p;
   unsigned int len;
};

struct payload {
    uint32_t state;                      /* One of the LIVEPATCH_STATE_*. */
    int32_t rc;                          /* 0 or -XEN_EXX. */
    bool reverted;                       /* Whether it was reverted. */
    bool safe_to_reapply;                /* Can apply safely after revert. */
    struct list_head list;               /* Linked to 'payload_list'. */
    const void *text_addr;               /* Virtual address of .text. */
    size_t text_size;                    /* .. and its size. */
    const void *rw_addr;                 /* Virtual address of .data. */
    size_t rw_size;                      /* .. and its size (if any). */
    const void *ro_addr;                 /* Virtual address of .rodata. */
    size_t ro_size;                      /* .. and its size (if any). */
    unsigned int pages;                  /* Total pages for [text,rw,ro]_addr */
    struct list_head applied_list;       /* Linked to 'applied_list'. */
    struct livepatch_func *funcs;        /* The array of functions to patch. */
    unsigned int nfuncs;                 /* Nr of functions to patch. */
    const struct livepatch_symbol *symtab; /* All symbols. */
    const char *strtab;                  /* Pointer to .strtab. */
    struct virtual_region region;        /* symbol, bug.frame patching and
                                            exception table (x86). */
    unsigned int nsyms;                  /* Nr of entries in .strtab and symbols. */
    struct livepatch_build_id id;        /* ELFNOTE_DESC(.note.gnu.build-id) of the payload. */
    struct livepatch_build_id dep;       /* ELFNOTE_DESC(.livepatch.depends). */
    livepatch_loadcall_t *const *load_funcs;   /* The array of funcs to call after */
    livepatch_unloadcall_t *const *unload_funcs;/* load and unload of the payload. */
    unsigned int n_load_funcs;           /* Nr of the funcs to load and execute. */
    unsigned int n_unload_funcs;         /* Nr of funcs to call durung unload. */
    char name[XEN_LIVEPATCH_NAME_SIZE];  /* Name of it. */
};

/* Defines an outstanding patching action. */
struct livepatch_work
{
    atomic_t semaphore;          /* Used to rendezvous CPUs in
                                    check_for_livepatch_work. */
    uint32_t timeout;            /* Timeout to do the operation. */
    struct payload *data;        /* The payload on which to act. */
    volatile bool_t do_work;     /* Signals work to do. */
    volatile bool_t ready;       /* Signals all CPUs synchronized. */
    unsigned int cmd;            /* Action request: LIVEPATCH_ACTION_* */
};

/* There can be only one outstanding patching action. */
static struct livepatch_work livepatch_work;

/*
 * Indicate whether the CPU needs to consult livepatch_work structure.
 * We want an per-cpu data structure otherwise the check_for_livepatch_work
 * would hammer a global livepatch_work structure on every guest VMEXIT.
 * Having an per-cpu lessens the load.
 */
static DEFINE_PER_CPU(bool_t, work_to_do);

static int get_name(const xen_livepatch_name_t *name, char *n)
{
    if ( !name->size || name->size > XEN_LIVEPATCH_NAME_SIZE )
        return -EINVAL;

    if ( name->pad[0] || name->pad[1] || name->pad[2] )
        return -EINVAL;

    if ( copy_from_guest(n, name->name, name->size) )
        return -EFAULT;

    if ( n[name->size - 1] )
        return -EINVAL;

    return 0;
}

static int verify_payload(const xen_sysctl_livepatch_upload_t *upload, char *n)
{
    if ( get_name(&upload->name, n) )
        return -EINVAL;

    if ( !upload->size )
        return -EINVAL;

    if ( upload->size > LIVEPATCH_MAX_SIZE )
        return -EINVAL;

    if ( !guest_handle_okay(upload->payload, upload->size) )
        return -EFAULT;

    return 0;
}

bool_t is_patch(const void *ptr)
{
    const struct payload *data;
    bool_t r = 0;

    /*
     * Only RCU locking since this list is only ever changed during apply
     * or revert context. And in case it dies there we need an safe list.
     */
    rcu_read_lock(&rcu_applied_lock);
    list_for_each_entry_rcu ( data, &applied_list, applied_list )
    {
        if ( (ptr >= data->rw_addr &&
              ptr < (data->rw_addr + data->rw_size)) ||
             (ptr >= data->ro_addr &&
              ptr < (data->ro_addr + data->ro_size)) ||
             (ptr >= data->text_addr &&
              ptr < (data->text_addr + data->text_size)) )
        {
            r = 1;
            break;
        }

    }
    rcu_read_unlock(&rcu_applied_lock);

    return r;
}

unsigned long livepatch_symbols_lookup_by_name(const char *symname)
{
    const struct payload *data;

    ASSERT(spin_is_locked(&payload_lock));
    list_for_each_entry ( data, &payload_list, list )
    {
        unsigned int i;

        for ( i = 0; i < data->nsyms; i++ )
        {
            if ( !data->symtab[i].new_symbol )
                continue;

            if ( !strcmp(data->symtab[i].name, symname) )
                return data->symtab[i].value;
        }
    }

    return 0;
}

static const char *livepatch_symbols_lookup(unsigned long addr,
                                            unsigned long *symbolsize,
                                            unsigned long *offset,
                                            char *namebuf)
{
    const struct payload *data;
    unsigned int i, best;
    const void *va = (const void *)addr;
    const char *n = NULL;

    /*
     * Only RCU locking since this list is only ever changed during apply
     * or revert context. And in case it dies there we need an safe list.
     */
    rcu_read_lock(&rcu_applied_lock);
    list_for_each_entry_rcu ( data, &applied_list, applied_list )
    {
        if ( va < data->text_addr ||
             va >= (data->text_addr + data->text_size) )
            continue;

        best = UINT_MAX;

        for ( i = 0; i < data->nsyms; i++ )
        {
            if ( data->symtab[i].value <= addr &&
                 (best == UINT_MAX ||
                  data->symtab[best].value < data->symtab[i].value) )
                best = i;
        }

        if ( best == UINT_MAX )
            break;

        if ( symbolsize )
            *symbolsize = data->symtab[best].size;
        if ( offset )
            *offset = addr - data->symtab[best].value;
        if ( namebuf )
            strlcpy(namebuf, data->name, KSYM_NAME_LEN);

        n = data->symtab[best].name;
        break;
    }
    rcu_read_unlock(&rcu_applied_lock);

    return n;
}

/* Lookup function's old address if not already resolved. */
static int resolve_old_address(struct livepatch_func *f,
                               const struct livepatch_elf *elf)
{
    if ( f->old_addr )
        return 0;

    f->old_addr = (void *)symbols_lookup_by_name(f->name);
    if ( !f->old_addr )
    {
        f->old_addr = (void *)livepatch_symbols_lookup_by_name(f->name);
        if ( !f->old_addr )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Could not resolve old address of %s\n",
                    elf->name, f->name);
            return -ENOENT;
        }
    }
    dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Resolved old address %s => %p\n",
            elf->name, f->name, f->old_addr);

    return 0;
}

static struct payload *find_payload(const char *name)
{
    struct payload *data, *found = NULL;

    ASSERT(spin_is_locked(&payload_lock));
    list_for_each_entry ( data, &payload_list, list )
    {
        if ( !strcmp(data->name, name) )
        {
            found = data;
            break;
        }
    }

    return found;
}

/*
 * Functions related to XEN_SYSCTL_LIVEPATCH_UPLOAD (see livepatch_upload), and
 * freeing payload (XEN_SYSCTL_LIVEPATCH_ACTION:LIVEPATCH_ACTION_UNLOAD).
 */

static void free_payload_data(struct payload *payload)
{
    /* Set to zero until "move_payload". */
    if ( !payload->pages )
        return;

    vfree((void *)payload->text_addr);

    payload->pages = 0;
}

/*
* calc_section computes the size (taking into account section alignment).
*
* Furthermore the offset is set with the offset from the start of the virtual
* address space for the payload (using passed in size). This is used in
* move_payload to figure out the destination location (load_addr).
*/
static void calc_section(const struct livepatch_elf_sec *sec, size_t *size,
                         unsigned int *offset)
{
    const Elf_Shdr *s = sec->sec;
    size_t align_size;

    align_size = ROUNDUP(*size, s->sh_addralign);
    *offset = align_size;
    *size = s->sh_size + align_size;
}

static int move_payload(struct payload *payload, struct livepatch_elf *elf)
{
    void *text_buf, *ro_buf, *rw_buf;
    unsigned int i, rw_buf_sec, rw_buf_cnt = 0;
    size_t size = 0;
    unsigned int *offset;
    int rc = 0;

    offset = xmalloc_array(unsigned int, elf->hdr->e_shnum);
    if ( !offset )
        return -ENOMEM;

    /* Compute size of different regions. */
    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        /*
         * Do nothing. These are .rel.text, rel.*, .symtab, .strtab,
         * and .shstrtab. For the non-relocate we allocate and copy these
         * via other means - and the .rel we can ignore as we only use it
         * once during loading.
         *
         * Also ignore sections with zero size. Those can be for example:
         * data, or .bss.
         */
        if ( livepatch_elf_ignore_section(elf->sec[i].sec) )
            offset[i] = UINT_MAX;
        else if ( (elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                   !(elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->text_size, &offset[i]);
        else if ( !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                  (elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->rw_size, &offset[i]);
        else if ( !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                  !(elf->sec[i].sec->sh_flags & SHF_WRITE) )
            calc_section(&elf->sec[i], &payload->ro_size, &offset[i]);
        else
        {
            dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Not supporting %s section!\n",
                    elf->name, elf->sec[i].name);
            rc = -EOPNOTSUPP;
            goto out;
        }
    }

    /*
     * Total of all three regions - RX, RW, and RO. We have to have
     * keep them in seperate pages so we PAGE_ALIGN the RX and RW to have
     * them on seperate pages. The last one will by default fall on its
     * own page.
     */
    size = PAGE_ALIGN(payload->text_size) + PAGE_ALIGN(payload->rw_size) +
                      payload->ro_size;

    size = PFN_UP(size); /* Nr of pages. */
    text_buf = vmalloc_xen(size * PAGE_SIZE);
    if ( !text_buf )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Could not allocate memory for payload!\n",
                elf->name);
        rc = -ENOMEM;
        goto out;
    }
    rw_buf = text_buf + PAGE_ALIGN(payload->text_size);
    ro_buf = rw_buf + PAGE_ALIGN(payload->rw_size);

    payload->pages = size;
    payload->text_addr = text_buf;
    payload->rw_addr = rw_buf;
    payload->ro_addr = ro_buf;

    for ( i = 1; i < elf->hdr->e_shnum; i++ )
    {
        if ( !livepatch_elf_ignore_section(elf->sec[i].sec) )
        {
            void *buf;

            if ( elf->sec[i].sec->sh_flags & SHF_EXECINSTR )
                buf = text_buf;
            else if ( elf->sec[i].sec->sh_flags & SHF_WRITE )
            {
                buf = rw_buf;
                rw_buf_sec = i;
                rw_buf_cnt++;
            }
            else
                buf = ro_buf;

            ASSERT(offset[i] != UINT_MAX);

            elf->sec[i].load_addr = buf + offset[i];

            /* Don't copy NOBITS - such as BSS. */
            if ( elf->sec[i].sec->sh_type != SHT_NOBITS )
            {
                memcpy(elf->sec[i].load_addr, elf->sec[i].data,
                       elf->sec[i].sec->sh_size);
                dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Loaded %s at %p\n",
                        elf->name, elf->sec[i].name, elf->sec[i].load_addr);
            }
            else
                memset(elf->sec[i].load_addr, 0, elf->sec[i].sec->sh_size);
        }
    }

    /* Only one RW section with non-zero size: .livepatch.funcs */
    if ( rw_buf_cnt == 1 &&
         !strcmp(elf->sec[rw_buf_sec].name, ELF_LIVEPATCH_FUNC) )
        payload->safe_to_reapply = true;
 out:
    xfree(offset);

    return rc;
}

static int secure_payload(struct payload *payload, struct livepatch_elf *elf)
{
    int rc = 0;
    unsigned int text_pages, rw_pages, ro_pages;

    text_pages = PFN_UP(payload->text_size);

    if ( text_pages )
    {
        rc = arch_livepatch_secure(payload->text_addr, text_pages, LIVEPATCH_VA_RX);
        if ( rc )
            return rc;
    }
    rw_pages = PFN_UP(payload->rw_size);
    if ( rw_pages )
    {
        rc = arch_livepatch_secure(payload->rw_addr, rw_pages, LIVEPATCH_VA_RW);
        if ( rc )
            return rc;
    }

    ro_pages = PFN_UP(payload->ro_size);
    if ( ro_pages )
        rc = arch_livepatch_secure(payload->ro_addr, ro_pages, LIVEPATCH_VA_RO);

    ASSERT(ro_pages + rw_pages + text_pages == payload->pages);

    return rc;
}

static int check_special_sections(const struct livepatch_elf *elf)
{
    unsigned int i;
    static const char *const names[] = { ELF_LIVEPATCH_FUNC,
                                         ELF_LIVEPATCH_DEPENDS,
                                         ELF_BUILD_ID_NOTE};
    DECLARE_BITMAP(found, ARRAY_SIZE(names)) = { 0 };

    for ( i = 0; i < ARRAY_SIZE(names); i++ )
    {
        const struct livepatch_elf_sec *sec;

        sec = livepatch_elf_sec_by_name(elf, names[i]);
        if ( !sec )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: %s is missing!\n",
                    elf->name, names[i]);
            return -EINVAL;
        }

        if ( !sec->sec->sh_size )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: %s is empty!\n",
                    elf->name, names[i]);
            return -EINVAL;
        }

        if ( test_and_set_bit(i, found) )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: %s was seen more than once!\n",
                    elf->name, names[i]);
            return -EINVAL;
        }
    }

    return 0;
}

static int prepare_payload(struct payload *payload,
                           struct livepatch_elf *elf)
{
    const struct livepatch_elf_sec *sec;
    unsigned int i;
    struct livepatch_func *f;
    struct virtual_region *region;
    const Elf_Note *n;

    sec = livepatch_elf_sec_by_name(elf, ELF_LIVEPATCH_FUNC);
    ASSERT(sec);
    if ( sec->sec->sh_size % sizeof(*payload->funcs) )
    {
        dprintk(XENLOG_ERR, LIVEPATCH "%s: Wrong size of "ELF_LIVEPATCH_FUNC"!\n",
                elf->name);
        return -EINVAL;
    }

    payload->funcs = sec->load_addr;
    payload->nfuncs = sec->sec->sh_size / sizeof(*payload->funcs);

    for ( i = 0; i < payload->nfuncs; i++ )
    {
        int rc;

        f = &(payload->funcs[i]);

        if ( f->version != LIVEPATCH_PAYLOAD_VERSION )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Wrong version (%u). Expected %d!\n",
                    elf->name, f->version, LIVEPATCH_PAYLOAD_VERSION);
            return -EOPNOTSUPP;
        }

        /* 'old_addr', 'new_addr', 'new_size' can all be zero. */
        if ( !f->old_size )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Address or size fields are zero!\n",
                    elf->name);
            return -EINVAL;
        }

        rc = arch_livepatch_verify_func(f);
        if ( rc )
            return rc;

        rc = resolve_old_address(f, elf);
        if ( rc )
            return rc;

        rc = livepatch_verify_distance(f);
        if ( rc )
            return rc;
    }

    sec = livepatch_elf_sec_by_name(elf, ".livepatch.hooks.load");
    if ( sec )
    {
        if ( sec->sec->sh_size % sizeof(*payload->load_funcs) )
            return -EINVAL;

        payload->load_funcs = sec->load_addr;
        payload->n_load_funcs = sec->sec->sh_size / sizeof(*payload->load_funcs);
    }

    sec = livepatch_elf_sec_by_name(elf, ".livepatch.hooks.unload");
    if ( sec )
    {
        if ( sec->sec->sh_size % sizeof(*payload->unload_funcs) )
            return -EINVAL;

        payload->unload_funcs = sec->load_addr;
        payload->n_unload_funcs = sec->sec->sh_size / sizeof(*payload->unload_funcs);
    }
    sec = livepatch_elf_sec_by_name(elf, ELF_BUILD_ID_NOTE);
    if ( sec )
    {
        const struct payload *data;

        n = sec->load_addr;

        if ( sec->sec->sh_size <= sizeof(*n) )
            return -EINVAL;

        if ( xen_build_id_check(n, sec->sec->sh_size,
                                &payload->id.p, &payload->id.len) )
            return -EINVAL;

        if ( !payload->id.len || !payload->id.p )
            return -EINVAL;

        /* Make sure it is not a duplicate. */
        list_for_each_entry ( data, &payload_list, list )
        {
            /* No way _this_ payload is on the list. */
            ASSERT(data != payload);
            if ( data->id.len == payload->id.len &&
                 !memcmp(data->id.p, payload->id.p, data->id.len) )
            {
                dprintk(XENLOG_DEBUG, LIVEPATCH "%s: Already loaded as %s!\n",
                        elf->name, data->name);
                return -EEXIST;
            }
        }
    }

    sec = livepatch_elf_sec_by_name(elf, ELF_LIVEPATCH_DEPENDS);
    if ( sec )
    {
        n = sec->load_addr;

        if ( sec->sec->sh_size <= sizeof(*n) )
            return -EINVAL;

        if ( xen_build_id_check(n, sec->sec->sh_size,
                                &payload->dep.p, &payload->dep.len) )
            return -EINVAL;

        if ( !payload->dep.len || !payload->dep.p )
            return -EINVAL;
    }

    /* Setup the virtual region with proper data. */
    region = &payload->region;

    region->symbols_lookup = livepatch_symbols_lookup;
    region->start = payload->text_addr;
    region->end = payload->text_addr + payload->text_size;

    /* Optional sections. */
    for ( i = 0; i < BUGFRAME_NR; i++ )
    {
        char str[14];

        snprintf(str, sizeof(str), ".bug_frames.%u", i);
        sec = livepatch_elf_sec_by_name(elf, str);
        if ( !sec )
            continue;

        if ( sec->sec->sh_size % sizeof(*region->frame[i].bugs) )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Wrong size of .bug_frames.%u!\n",
                    elf->name, i);
            return -EINVAL;
        }

        region->frame[i].bugs = sec->load_addr;
        region->frame[i].n_bugs = sec->sec->sh_size /
                                  sizeof(*region->frame[i].bugs);
    }

    sec = livepatch_elf_sec_by_name(elf, ".altinstructions");
    if ( sec )
    {
#ifdef CONFIG_HAS_ALTERNATIVE
        struct alt_instr *a, *start, *end;

        if ( sec->sec->sh_size % sizeof(*a) )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Size of .alt_instr is not multiple of %zu!\n",
                    elf->name, sizeof(*a));
            return -EINVAL;
        }

        start = sec->load_addr;
        end = sec->load_addr + sec->sec->sh_size;

        for ( a = start; a < end; a++ )
        {
            const void *instr = ALT_ORIG_PTR(a);
            const void *replacement = ALT_REPL_PTR(a);

            if ( (instr < region->start && instr >= region->end) ||
                 (replacement < region->start && replacement >= region->end) )
            {
                dprintk(XENLOG_ERR, LIVEPATCH "%s Alt patching outside payload: %p!\n",
                        elf->name, instr);
                return -EINVAL;
            }
        }
        apply_alternatives(start, end);
#else
        dprintk(XENLOG_ERR, LIVEPATCH "%s: We don't support alternative patching!\n",
                elf->name);
        return -EOPNOTSUPP;
#endif
    }

    sec = livepatch_elf_sec_by_name(elf, ".ex_table");
    if ( sec )
    {
#ifdef CONFIG_HAS_EX_TABLE
        struct exception_table_entry *s, *e;

        if ( !sec->sec->sh_size ||
             (sec->sec->sh_size % sizeof(*region->ex)) )
        {
            dprintk(XENLOG_ERR, LIVEPATCH "%s: Wrong size of .ex_table (exp:%lu vs %lu)!\n",
                    elf->name, sizeof(*region->ex),
                    sec->sec->sh_size);
            return -EINVAL;
        }

        s = sec->load_addr;
        e = sec->load_addr + sec->sec->sh_size;

        sort_exception_table(s ,e);

        region->ex = s;
        region->ex_end = e;
#else
        dprintk(XENLOG_ERR, LIVEPATCH "%s: We don't support .ex_table!\n",
                elf->name);
        return -EOPNOTSUPP;
#endif
    }

    return 0;
}

static bool_t is_payload_symbol(const struct livepatch_elf *elf,
                                const struct livepatch_elf_sym *sym)
{
    if ( sym->sym->st_shndx == SHN_UNDEF ||
         sym->sym->st_shndx >= elf->hdr->e_shnum )
        return 0;

    /*
     * The payload is not a final image as we dynmically link against it.
     * As such the linker has left symbols we don't care about and which
     * binutils would have removed had it be a final image. Hence we:
     * - For SHF_ALLOC - ignore symbols referring to sections that are not
     *   loaded.
     */
    if ( !(elf->sec[sym->sym->st_shndx].sec->sh_flags & SHF_ALLOC) )
        return 0;

    /* - And ignore empty symbols (\0). */
    if ( *sym->name == '\0' )
        return 0;

    /*
     * - For SHF_MERGE - ignore local symbols referring to mergeable sections.
     *    (ld squashes them all in one section and discards the symbols) when
     *    those symbols start with '.L' (like .LCx). Those are intermediate
     *    artifacts of assembly.
     *
     * See elf_link_input_bfd and _bfd_elf_is_local_label_name in binutils.
     */
    if ( (elf->sec[sym->sym->st_shndx].sec->sh_flags & SHF_MERGE) &&
         !strncmp(sym->name, ".L", 2) )
        return 0;

    return arch_livepatch_symbol_ok(elf, sym);
}

static int build_symbol_table(struct payload *payload,
                              const struct livepatch_elf *elf)
{
    unsigned int i, j, nsyms = 0;
    size_t strtab_len = 0;
    struct livepatch_symbol *symtab;
    char *strtab;

    ASSERT(payload->nfuncs);

    /* Recall that section @0 is always NULL. */
    for ( i = 1; i < elf->nsym; i++ )
    {
        if ( is_payload_symbol(elf, elf->sym + i) )
        {
            nsyms++;
            strtab_len += strlen(elf->sym[i].name) + 1;
        }
    }

    symtab = xmalloc_array(struct livepatch_symbol, nsyms);
    strtab = xmalloc_array(char, strtab_len);

    if ( !strtab || !symtab )
    {
        xfree(strtab);
        xfree(symtab);
        return -ENOMEM;
    }

    nsyms = 0;
    strtab_len = 0;
    for ( i = 1; i < elf->nsym; i++ )
    {
        if ( is_payload_symbol(elf, elf->sym + i) )
        {
            symtab[nsyms].name = strtab + strtab_len;
            symtab[nsyms].size = elf->sym[i].sym->st_size;
            symtab[nsyms].value = elf->sym[i].sym->st_value;
            symtab[nsyms].new_symbol = 0; /* May be overwritten below. */
            strtab_len += strlcpy(strtab + strtab_len, elf->sym[i].name,
                                  KSYM_NAME_LEN) + 1;
            nsyms++;
        }
    }

    for ( i = 0; i < nsyms; i++ )
    {
        bool_t found = 0;

        for ( j = 0; j < payload->nfuncs; j++ )
        {
            if ( symtab[i].value == (unsigned long)payload->funcs[j].new_addr )
            {
                found = 1;
                break;
            }
        }

        if ( !found )
        {
            if ( symbols_lookup_by_name(symtab[i].name) ||
                 livepatch_symbols_lookup_by_name(symtab[i].name) )
            {
                dprintk(XENLOG_ERR, LIVEPATCH "%s: duplicate new symbol: %s\n",
                        elf->name, symtab[i].name);
                xfree(symtab);
                xfree(strtab);
                return -EEXIST;
            }
            symtab[i].new_symbol = 1;
            dprintk(XENLOG_DEBUG, LIVEPATCH "%s: new symbol %s\n",
                     elf->name, symtab[i].name);
        }
        else
        {
            /* new_symbol is not set. */
            dprintk(XENLOG_DEBUG, LIVEPATCH "%s: overriding symbol %s\n",
                    elf->name, symtab[i].name);
        }
    }

    payload->symtab = symtab;
    payload->strtab = strtab;
    payload->nsyms = nsyms;

    return 0;
}

static void free_payload(struct payload *data)
{
    ASSERT(spin_is_locked(&payload_lock));
    list_del(&data->list);
    payload_cnt--;
    payload_version++;
    free_payload_data(data);
    xfree((void *)data->symtab);
    xfree((void *)data->strtab);
    xfree(data);
}

static int load_payload_data(struct payload *payload, void *raw, size_t len)
{
    struct livepatch_elf elf = { .name = payload->name, .len = len };
    int rc = 0;

    rc = livepatch_elf_load(&elf, raw);
    if ( rc )
        goto out;

    rc = move_payload(payload, &elf);
    if ( rc )
        goto out;

    rc = livepatch_elf_resolve_symbols(&elf);
    if ( rc )
        goto out;

    rc = livepatch_elf_perform_relocs(&elf);
    if ( rc )
        goto out;

    rc = check_special_sections(&elf);
    if ( rc )
        goto out;

    rc = prepare_payload(payload, &elf);
    if ( rc )
        goto out;

    rc = build_symbol_table(payload, &elf);
    if ( rc )
        goto out;

    rc = secure_payload(payload, &elf);

 out:
    if ( rc )
        free_payload_data(payload);

    /* Free our temporary data structure. */
    livepatch_elf_free(&elf);

    return rc;
}

static int livepatch_upload(xen_sysctl_livepatch_upload_t *upload)
{
    struct payload *data, *found;
    char n[XEN_LIVEPATCH_NAME_SIZE];
    void *raw_data;
    int rc;

    rc = verify_payload(upload, n);
    if ( rc )
        return rc;

    data = xzalloc(struct payload);
    raw_data = vmalloc(upload->size);

    spin_lock(&payload_lock);

    found = find_payload(n);
    if ( IS_ERR(found) )
        rc = PTR_ERR(found);
    else if ( found )
        rc = -EEXIST;
    else if ( !data || !raw_data )
        rc = -ENOMEM;
    else if ( __copy_from_guest(raw_data, upload->payload, upload->size) )
        rc = -EFAULT;
    else
    {
        memcpy(data->name, n, strlen(n));

        rc = load_payload_data(data, raw_data, upload->size);
        if ( rc )
            goto out;

        data->state = LIVEPATCH_STATE_CHECKED;
        INIT_LIST_HEAD(&data->list);
        INIT_LIST_HEAD(&data->applied_list);

        list_add_tail(&data->list, &payload_list);
        payload_cnt++;
        payload_version++;
    }

 out:
    spin_unlock(&payload_lock);

    vfree(raw_data);

    if ( rc && data )
    {
        xfree((void *)data->symtab);
        xfree((void *)data->strtab);
        xfree(data);
    }

    return rc;
}

static int livepatch_get(xen_sysctl_livepatch_get_t *get)
{
    struct payload *data;
    int rc;
    char n[XEN_LIVEPATCH_NAME_SIZE];

    rc = get_name(&get->name, n);
    if ( rc )
        return rc;

    spin_lock(&payload_lock);

    data = find_payload(n);
    if ( IS_ERR_OR_NULL(data) )
    {
        spin_unlock(&payload_lock);

        if ( !data )
            return -ENOENT;

        return PTR_ERR(data);
    }

    get->status.state = data->state;
    get->status.rc = data->rc;

    spin_unlock(&payload_lock);

    return 0;
}

static int livepatch_list(xen_sysctl_livepatch_list_t *list)
{
    xen_livepatch_status_t status;
    struct payload *data;
    unsigned int idx = 0, i = 0;
    int rc = 0;

    if ( list->nr > 1024 )
        return -E2BIG;

    if ( list->pad )
        return -EINVAL;

    if ( list->nr &&
         (!guest_handle_okay(list->status, list->nr) ||
          !guest_handle_okay(list->name, XEN_LIVEPATCH_NAME_SIZE * list->nr) ||
          !guest_handle_okay(list->len, list->nr)) )
        return -EINVAL;

    spin_lock(&payload_lock);
    if ( list->idx >= payload_cnt && payload_cnt )
    {
        spin_unlock(&payload_lock);
        return -EINVAL;
    }

    if ( list->nr )
    {
        list_for_each_entry( data, &payload_list, list )
        {
            uint32_t len;

            if ( list->idx > i++ )
                continue;

            status.state = data->state;
            status.rc = data->rc;
            len = strlen(data->name) + 1;

            /* N.B. 'idx' != 'i'. */
            if ( __copy_to_guest_offset(list->name, idx * XEN_LIVEPATCH_NAME_SIZE,
                                        data->name, len) ||
                __copy_to_guest_offset(list->len, idx, &len, 1) ||
                __copy_to_guest_offset(list->status, idx, &status, 1) )
            {
                rc = -EFAULT;
                break;
            }

            idx++;

            if ( (idx >= list->nr) || hypercall_preempt_check() )
                break;
        }
    }
    list->nr = payload_cnt - i; /* Remaining amount. */
    list->version = payload_version;
    spin_unlock(&payload_lock);

    /* And how many we have processed. */
    return rc ? : idx;
}

/*
 * The following functions get the CPUs into an appropriate state and
 * apply (or revert) each of the payload's functions. This is needed
 * for XEN_SYSCTL_LIVEPATCH_ACTION operation (see livepatch_action).
 */

static int apply_payload(struct payload *data)
{
    unsigned int i;
    int rc;

    printk(XENLOG_INFO LIVEPATCH "%s: Applying %u functions\n",
            data->name, data->nfuncs);

    rc = arch_livepatch_quiesce();
    if ( rc )
    {
        printk(XENLOG_ERR LIVEPATCH "%s: unable to quiesce!\n", data->name);
        return rc;
    }

    /*
     * Since we are running with IRQs disabled and the hooks may call common
     * code - which expects certain spinlocks to run with IRQs enabled - we
     * temporarily disable the spin locks IRQ state checks.
     */
    spin_debug_disable();
    for ( i = 0; i < data->n_load_funcs; i++ )
        data->load_funcs[i]();
    spin_debug_enable();

    ASSERT(!local_irq_is_enabled());

    for ( i = 0; i < data->nfuncs; i++ )
        arch_livepatch_apply(&data->funcs[i]);

    arch_livepatch_revive();

    /*
     * We need RCU variant (which has barriers) in case we crash here.
     * The applied_list is iterated by the trap code.
     */
    list_add_tail_rcu(&data->applied_list, &applied_list);
    register_virtual_region(&data->region);

    return 0;
}

static int revert_payload(struct payload *data)
{
    unsigned int i;
    int rc;

    printk(XENLOG_INFO LIVEPATCH "%s: Reverting\n", data->name);

    rc = arch_livepatch_quiesce();
    if ( rc )
    {
        printk(XENLOG_ERR LIVEPATCH "%s: unable to quiesce!\n", data->name);
        return rc;
    }

    for ( i = 0; i < data->nfuncs; i++ )
        arch_livepatch_revert(&data->funcs[i]);

    /*
     * Since we are running with IRQs disabled and the hooks may call common
     * code - which expects certain spinlocks to run with IRQs enabled - we
     * temporarily disable the spin locks IRQ state checks.
     */
    spin_debug_disable();
    for ( i = 0; i < data->n_unload_funcs; i++ )
        data->unload_funcs[i]();
    spin_debug_enable();

    ASSERT(!local_irq_is_enabled());

    arch_livepatch_revive();

    /*
     * We need RCU variant (which has barriers) in case we crash here.
     * The applied_list is iterated by the trap code.
     */
    list_del_rcu(&data->applied_list);
    unregister_virtual_region(&data->region);

    data->reverted = true;
    return 0;
}

/*
 * This function is executed having all other CPUs with no deep stack (we may
 * have cpu_idle on it) and IRQs disabled.
 */
static void livepatch_do_action(void)
{
    int rc;
    struct payload *data, *other, *tmp;

    data = livepatch_work.data;
    /*
     * This function and the transition from asm to C code should be the only
     * one on any stack. No need to lock the payload list or applied list.
     */
    switch ( livepatch_work.cmd )
    {
    case LIVEPATCH_ACTION_APPLY:
        rc = apply_payload(data);
        if ( rc == 0 )
            data->state = LIVEPATCH_STATE_APPLIED;
        break;

    case LIVEPATCH_ACTION_REVERT:
        rc = revert_payload(data);
        if ( rc == 0 )
            data->state = LIVEPATCH_STATE_CHECKED;
        break;

    case LIVEPATCH_ACTION_REPLACE:
        rc = 0;
        /*
	 * N.B: Use 'applied_list' member, not 'list'. We also abuse the
	 * the 'normal' list iterator as the list is an RCU one.
	 */
        list_for_each_entry_safe_reverse ( other, tmp, &applied_list, applied_list )
        {
            other->rc = revert_payload(other);
            if ( other->rc == 0 )
                other->state = LIVEPATCH_STATE_CHECKED;
            else
            {
                rc = -EINVAL;
                break;
            }
        }

        if ( rc == 0 )
        {
            rc = apply_payload(data);
            if ( rc == 0 )
                data->state = LIVEPATCH_STATE_APPLIED;
        }
        break;

    default:
        rc = -EINVAL; /* Make GCC5 happy. */
        ASSERT_UNREACHABLE();
        break;
    }

    /* We must set rc as livepatch_action sets it to -EAGAIN when kicking of. */
    data->rc = rc;
}

static bool_t is_work_scheduled(const struct payload *data)
{
    ASSERT(spin_is_locked(&payload_lock));

    return livepatch_work.do_work && livepatch_work.data == data;
}

static int schedule_work(struct payload *data, uint32_t cmd, uint32_t timeout)
{
    ASSERT(spin_is_locked(&payload_lock));

    /* Fail if an operation is already scheduled. */
    if ( livepatch_work.do_work )
        return -EBUSY;

    if ( !get_cpu_maps() )
    {
        printk(XENLOG_ERR LIVEPATCH "%s: unable to get cpu_maps lock!\n",
               data->name);
        return -EBUSY;
    }

    livepatch_work.cmd = cmd;
    livepatch_work.data = data;
    livepatch_work.timeout = timeout ?: MILLISECS(30);

    dprintk(XENLOG_DEBUG, LIVEPATCH "%s: timeout is %"PRI_stime"ms\n",
            data->name, livepatch_work.timeout / MILLISECS(1));

    atomic_set(&livepatch_work.semaphore, -1);

    livepatch_work.ready = 0;

    smp_wmb();

    livepatch_work.do_work = 1;
    this_cpu(work_to_do) = 1;

    put_cpu_maps();

    return 0;
}

static void reschedule_fn(void *unused)
{
    this_cpu(work_to_do) = 1;
    raise_softirq(SCHEDULE_SOFTIRQ);
}

static int livepatch_spin(atomic_t *counter, s_time_t timeout,
                          unsigned int cpus, const char *s)
{
    int rc = 0;

    while ( atomic_read(counter) != cpus && NOW() < timeout )
        cpu_relax();

    /* Log & abort. */
    if ( atomic_read(counter) != cpus )
    {
        printk(XENLOG_ERR LIVEPATCH "%s: Timed out on semaphore in %s quiesce phase %u/%u\n",
               livepatch_work.data->name, s, atomic_read(counter), cpus);
        rc = -EBUSY;
        livepatch_work.data->rc = rc;
        smp_wmb();
        livepatch_work.do_work = 0;
    }

    return rc;
}

/*
 * The main function which manages the work of quiescing the system and
 * patching code.
 */
void check_for_livepatch_work(void)
{
#define ACTION(x) [LIVEPATCH_ACTION_##x] = #x
    static const char *const names[] = {
            ACTION(APPLY),
            ACTION(REVERT),
            ACTION(REPLACE),
    };
#undef ACTION
    unsigned int cpu = smp_processor_id();
    s_time_t timeout;
    unsigned long flags;

    /* Fast path: no work to do. */
    if ( !per_cpu(work_to_do, cpu ) )
        return;

    smp_rmb();
    /* In case we aborted, other CPUs can skip right away. */
    if ( !livepatch_work.do_work )
    {
        per_cpu(work_to_do, cpu) = 0;
        return;
    }

    ASSERT(local_irq_is_enabled());

    /* Set at -1, so will go up to num_online_cpus - 1. */
    if ( atomic_inc_and_test(&livepatch_work.semaphore) )
    {
        struct payload *p;
        unsigned int cpus;

        p = livepatch_work.data;
        if ( !get_cpu_maps() )
        {
            printk(XENLOG_ERR LIVEPATCH "%s: CPU%u - unable to get cpu_maps lock!\n",
                   p->name, cpu);
            per_cpu(work_to_do, cpu) = 0;
            livepatch_work.data->rc = -EBUSY;
            smp_wmb();
            livepatch_work.do_work = 0;
            /*
             * Do NOT decrement livepatch_work.semaphore down - as that may cause
             * the other CPU (which may be at this point ready to increment it)
             * to assume the role of master and then needlessly time out
             * out (as do_work is zero).
             */
            return;
        }
        /* "Mask" NMIs. */
        arch_livepatch_mask();

        barrier(); /* MUST do it after get_cpu_maps. */
        cpus = num_online_cpus() - 1;

        if ( cpus )
        {
            dprintk(XENLOG_DEBUG, LIVEPATCH "%s: CPU%u - IPIing the other %u CPUs\n",
                    p->name, cpu, cpus);
            smp_call_function(reschedule_fn, NULL, 0);
        }

        timeout = livepatch_work.timeout + NOW();
        if ( livepatch_spin(&livepatch_work.semaphore, timeout, cpus, "CPU") )
            goto abort;

        /* All CPUs are waiting, now signal to disable IRQs. */
        atomic_set(&livepatch_work.semaphore, 0);
        /*
         * MUST have a barrier after semaphore so that the other CPUs don't
         * leak out of the 'Wait for all CPUs to rendezvous' loop and increment
         * 'semaphore' before we set it to zero.
         */
        smp_wmb();
        livepatch_work.ready = 1;

        if ( !livepatch_spin(&livepatch_work.semaphore, timeout, cpus, "IRQ") )
        {
            local_irq_save(flags);
            /* Do the patching. */
            livepatch_do_action();
            /* Serialize and flush out the CPU via CPUID instruction (on x86). */
            arch_livepatch_post_action();
            local_irq_restore(flags);
        }

 abort:
        arch_livepatch_unmask();

        per_cpu(work_to_do, cpu) = 0;
        livepatch_work.do_work = 0;

        /* put_cpu_maps has an barrier(). */
        put_cpu_maps();

        printk(XENLOG_INFO LIVEPATCH "%s finished %s with rc=%d\n",
               p->name, names[livepatch_work.cmd], p->rc);
    }
    else
    {
        /* Wait for all CPUs to rendezvous. */
        while ( livepatch_work.do_work && !livepatch_work.ready )
            cpu_relax();

        /* Disable IRQs and signal. */
        local_irq_save(flags);
        /*
         * We re-use the sempahore, so MUST have it reset by master before
         * we exit the loop above.
         */
        atomic_inc(&livepatch_work.semaphore);

        /* Wait for patching to complete. */
        while ( livepatch_work.do_work )
            cpu_relax();

        /* To flush out pipeline. */
        arch_livepatch_post_action();
        local_irq_restore(flags);

        per_cpu(work_to_do, cpu) = 0;
    }
}

/*
 * Only allow dependent payload is applied on top of the correct
 * build-id.
 *
 * This enforces an stacking order - the first payload MUST be against the
 * hypervisor. The second against the first payload, and so on.
 *
 * Unless the 'internal' parameter is used - in which case we only
 * check against the hypervisor.
 */
static int build_id_dep(struct payload *payload, bool_t internal)
{
    const void *id = NULL;
    unsigned int len = 0;
    int rc;
    const char *name = "hypervisor";

    ASSERT(payload->dep.len && payload->dep.p);

    /* First time user is against hypervisor. */
    if ( internal )
    {
        rc = xen_build_id(&id, &len);
        if ( rc )
            return rc;
    }
    else
    {
        /* We should be against the last applied one. */
        const struct payload *data;

        data = list_last_entry(&applied_list, struct payload, applied_list);

        id = data->id.p;
        len = data->id.len;
        name = data->name;
    }

    if ( payload->dep.len != len ||
         memcmp(id, payload->dep.p, len) )
    {
        dprintk(XENLOG_ERR, "%s%s: check against %s build-id failed!\n",
                LIVEPATCH, payload->name, name);
        return -EINVAL;
    }

    return 0;
}

static int livepatch_action(xen_sysctl_livepatch_action_t *action)
{
    struct payload *data;
    char n[XEN_LIVEPATCH_NAME_SIZE];
    int rc;

    rc = get_name(&action->name, n);
    if ( rc )
        return rc;

    spin_lock(&payload_lock);

    data = find_payload(n);
    if ( IS_ERR_OR_NULL(data) )
    {
        spin_unlock(&payload_lock);

        if ( !data )
            return -ENOENT;

        return PTR_ERR(data);
    }

    if ( is_work_scheduled(data) )
    {
        rc = -EBUSY;
        goto out;
    }

    switch ( action->cmd )
    {
    case LIVEPATCH_ACTION_UNLOAD:
        if ( data->state == LIVEPATCH_STATE_CHECKED )
        {
            free_payload(data);
            /* No touching 'data' from here on! */
            data = NULL;
        }
        else
            rc = -EINVAL;
        break;

    case LIVEPATCH_ACTION_REVERT:
        if ( data->state == LIVEPATCH_STATE_APPLIED )
        {
            const struct payload *p;

            p = list_last_entry(&applied_list, struct payload, applied_list);
            ASSERT(p);
            /* We should be the last applied one. */
            if ( p != data )
            {
                dprintk(XENLOG_ERR, "%s%s: can't unload. Top is %s!\n",
                        LIVEPATCH, data->name, p->name);
                rc = -EBUSY;
                break;
            }
            data->rc = -EAGAIN;
            rc = schedule_work(data, action->cmd, action->timeout);
        }
        break;

    case LIVEPATCH_ACTION_APPLY:
        if ( data->state == LIVEPATCH_STATE_CHECKED )
        {
            /*
             * It is unsafe to apply an reverted payload as the .data (or .bss)
             * may not be in in pristine condition. Hence MUST unload and then
             * apply patch again. Unless the payload has only one
             * RW section (.livepatch.funcs).
             */
            if ( data->reverted && !data->safe_to_reapply )
            {
                dprintk(XENLOG_ERR, "%s%s: can't revert as payload has .data. Please unload!\n",
                        LIVEPATCH, data->name);
                data->rc = -EINVAL;
                break;
            }

            rc = build_id_dep(data, !!list_empty(&applied_list));
            if ( rc )
                break;
            data->rc = -EAGAIN;
            rc = schedule_work(data, action->cmd, action->timeout);
        }
        break;

    case LIVEPATCH_ACTION_REPLACE:
        if ( data->state == LIVEPATCH_STATE_CHECKED )
        {
            rc = build_id_dep(data, 1 /* against hypervisor. */);
            if ( rc )
                break;
            data->rc = -EAGAIN;
            rc = schedule_work(data, action->cmd, action->timeout);
        }
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
    }

 out:
    spin_unlock(&payload_lock);

    return rc;
}

int livepatch_op(xen_sysctl_livepatch_op_t *livepatch)
{
    int rc;

    if ( livepatch->pad )
        return -EINVAL;

    switch ( livepatch->cmd )
    {
    case XEN_SYSCTL_LIVEPATCH_UPLOAD:
        rc = livepatch_upload(&livepatch->u.upload);
        break;

    case XEN_SYSCTL_LIVEPATCH_GET:
        rc = livepatch_get(&livepatch->u.get);
        break;

    case XEN_SYSCTL_LIVEPATCH_LIST:
        rc = livepatch_list(&livepatch->u.list);
        break;

    case XEN_SYSCTL_LIVEPATCH_ACTION:
        rc = livepatch_action(&livepatch->u.action);
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
   }

    return rc;
}

static const char *state2str(unsigned int state)
{
#define STATE(x) [LIVEPATCH_STATE_##x] = #x
    static const char *const names[] = {
            STATE(CHECKED),
            STATE(APPLIED),
    };
#undef STATE

    if ( state >= ARRAY_SIZE(names) || !names[state] )
        return "unknown";

    return names[state];
}

static void livepatch_printall(unsigned char key)
{
    struct payload *data;
    const void *binary_id = NULL;
    unsigned int len = 0;
    unsigned int i;

    printk("'%c' pressed - Dumping all livepatch patches\n", key);

    if ( !xen_build_id(&binary_id, &len) )
        printk("build-id: %*phN\n", len, binary_id);

    if ( !spin_trylock(&payload_lock) )
    {
        printk("Lock held. Try again.\n");
        return;
    }

    list_for_each_entry ( data, &payload_list, list )
    {
        printk(" name=%s state=%s(%d) %p (.data=%p, .rodata=%p) using %u pages.\n",
               data->name, state2str(data->state), data->state, data->text_addr,
               data->rw_addr, data->ro_addr, data->pages);

        for ( i = 0; i < data->nfuncs; i++ )
        {
            struct livepatch_func *f = &(data->funcs[i]);
            printk("    %s patch %p(%u) with %p (%u)\n",
                   f->name, f->old_addr, f->old_size, f->new_addr, f->new_size);

            if ( i && !(i % 64) )
            {
                spin_unlock(&payload_lock);
                process_pending_softirqs();
                if ( spin_trylock(&payload_lock) )
                {
                    printk("Couldn't reacquire lock. Try again.\n");
                    return;
                }
            }
        }
        if ( data->id.len )
            printk("build-id=%*phN\n", data->id.len, data->id.p);

        if ( data->dep.len )
            printk("depend-on=%*phN\n", data->dep.len, data->dep.p);
    }

    spin_unlock(&payload_lock);
}

static int __init livepatch_init(void)
{
    register_keyhandler('x', livepatch_printall, "print livepatch info", 1);

    arch_livepatch_init();
    return 0;
}
__initcall(livepatch_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
