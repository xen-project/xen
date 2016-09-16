/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 */

#ifndef __XEN_LIVEPATCH_PAYLOAD_H__
#define __XEN_LIVEPATCH_PAYLOAD_H__

/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */
typedef void livepatch_loadcall_t(void);
typedef void livepatch_unloadcall_t(void);

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
 */
#define LIVEPATCH_LOAD_HOOK(_fn) \
    livepatch_loadcall_t *__attribute__((weak)) \
        const livepatch_load_data_##_fn __section(".livepatch.hooks.load") = _fn;

/*
 * LIVEPATCH_UNLOAD_HOOK macro
 *
 * Same as LOAD hook with s/load/unload/
 */
#define LIVEPATCH_UNLOAD_HOOK(_fn) \
     livepatch_unloadcall_t *__attribute__((weak)) \
        const livepatch_unload_data_##_fn __section(".livepatch.hooks.unload") = _fn;

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
