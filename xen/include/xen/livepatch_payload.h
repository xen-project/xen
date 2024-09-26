/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_LIVEPATCH_PAYLOAD_H__
#define __XEN_LIVEPATCH_PAYLOAD_H__
#include <xen/virtual_region.h>

/* To contain the ELF Note header. */
struct livepatch_build_id {
   const void *p;
   unsigned int len;
};

typedef struct payload livepatch_payload_t;

/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */
typedef void livepatch_loadcall_t(void);
typedef void livepatch_unloadcall_t(void);

typedef int livepatch_precall_t(livepatch_payload_t *arg);
typedef int livepatch_actioncall_t(livepatch_payload_t *arg);
typedef void livepatch_postcall_t(livepatch_payload_t *arg);

struct livepatch_hooks {
    struct {
        livepatch_precall_t *const *pre;
        livepatch_actioncall_t *const *action;
        livepatch_postcall_t *const *post;
    } apply, revert;
};

struct livepatch_metadata {
    const char *data; /* Ptr to .modinfo section with ASCII data. */
    uint32_t len;     /* Length of the metadata section. */
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
    const struct livepatch_func *funcs;  /* The array of functions to patch. */
    struct livepatch_fstate *fstate;     /* State of patched functions. */
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
    struct livepatch_hooks hooks;        /* Pre and post hooks for apply and revert */
    unsigned int n_load_funcs;           /* Nr of the funcs to load and execute. */
    unsigned int n_unload_funcs;         /* Nr of funcs to call durung unload. */
    char name[XEN_LIVEPATCH_NAME_SIZE];  /* Name of it. */
    struct livepatch_metadata metadata;  /* Module meta data record */
};

/*
 * LIVEPATCH_LOAD_HOOK macro
 *
 * Declares a function pointer to be allocated in a new
 * .livepatch.hook.load section.  This livepatch_load_data symbol is later
 * stripped by create-diff-object so that it can be declared in multiple
 * objects that are later linked together, avoiding global symbol
 * collision.  Since multiple hooks can be registered, the
 * .livepatch.hook.load section is a table of functions that will be
 * executed in series by the livepatch infrastructure at patch load time.
 *
 * Note the load hook is executed in quiesced context.
 */
#define LIVEPATCH_LOAD_HOOK(_fn) \
    livepatch_loadcall_t *__weak \
        const livepatch_load_data_##_fn __section(".livepatch.hooks.load") = _fn;

/*
 * LIVEPATCH_UNLOAD_HOOK macro
 *
 * Same as LOAD hook with s/load/unload/
 */
#define LIVEPATCH_UNLOAD_HOOK(_fn) \
     livepatch_unloadcall_t *__weak \
        const livepatch_unload_data_##_fn __section(".livepatch.hooks.unload") = _fn;

/*
 * Pre/Post action hooks.
 *
 * This hooks are executed before or after the livepatch application. Pre hooks
 * can veto the application/revert of the livepatch.  They are not executed in
 * quiesced context.  All of pre and post hooks are considered vetoing, and
 * hence filling any of those will block the usage of the REPLACE action.
 *
 * Each of the hooks below can only be set once per livepatch payload.
 */
#define LIVEPATCH_PREAPPLY_HOOK(_fn) \
    livepatch_precall_t *__attribute__((weak, used)) \
        const livepatch_preapply_data_##_fn __section(".livepatch.hooks.preapply") = _fn;

#define LIVEPATCH_POSTAPPLY_HOOK(_fn) \
    livepatch_postcall_t *__attribute__((weak, used)) \
        const livepatch_postapply_data_##_fn __section(".livepatch.hooks.postapply") = _fn;

#define LIVEPATCH_PREREVERT_HOOK(_fn) \
    livepatch_precall_t *__attribute__((weak, used)) \
        const livepatch_prerevert_data_##_fn __section(".livepatch.hooks.prerevert") = _fn;

#define LIVEPATCH_POSTREVERT_HOOK(_fn) \
    livepatch_postcall_t *__attribute__((weak, used)) \
        const livepatch_postrevert_data_##_fn __section(".livepatch.hooks.postrevert") = _fn;

/*
 * Action replacement hooks.
 *
 * The following hooks replace the hypervisor implementation for the livepatch
 * application and revert routines.  When filling the hooks below the native
 * apply and revert routines will not be executed, so the provided hooks need
 * to make sure the state of the payload after apply or revert is as expected
 * by the livepatch logic.
 */
#define LIVEPATCH_APPLY_HOOK(_fn) \
    livepatch_actioncall_t *__attribute__((weak, used)) \
        const livepatch_apply_data_##_fn __section(".livepatch.hooks.apply") = _fn;

#define LIVEPATCH_REVERT_HOOK(_fn) \
    livepatch_actioncall_t *__attribute__((weak, used)) \
        const livepatch_revert_data_##_fn __section(".livepatch.hooks.revert") = _fn;

#endif /* __XEN_LIVEPATCH_PAYLOAD_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
