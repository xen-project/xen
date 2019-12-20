/*
 * Copyright (c) 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 */

#include "config.h"
#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#include <public/sysctl.h>

static const char hello_world_patch_this_fnc[] = "xen_extra_version";
extern const char *xen_hello_world(void);

static unsigned int apply_cnt;
static unsigned int revert_cnt;

static int apply_hook(livepatch_payload_t *payload)
{
    int i;

    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);

    for (i = 0; i < payload->nfuncs; i++)
    {
        struct livepatch_func *func = &payload->funcs[i];

        func->applied = LIVEPATCH_FUNC_APPLIED;
        apply_cnt++;

        printk(KERN_DEBUG "%s: applying: %s\n", __func__, func->name);
    }

    printk(KERN_DEBUG "%s: Hook done.\n", __func__);

    return 0;
}

static int revert_hook(livepatch_payload_t *payload)
{
    int i;

    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);

    for (i = 0; i < payload->nfuncs; i++)
    {
        struct livepatch_func *func = &payload->funcs[i];

        func->applied = LIVEPATCH_FUNC_NOT_APPLIED;
        revert_cnt++;

        printk(KERN_DEBUG "%s: reverting: %s\n", __func__, func->name);
    }

    printk(KERN_DEBUG "%s: Hook done.\n", __func__);

    return 0;
}

static void post_revert_hook(livepatch_payload_t *payload)
{
    int i;

    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);

    for (i = 0; i < payload->nfuncs; i++)
    {
        struct livepatch_func *func = &payload->funcs[i];

        printk(KERN_DEBUG "%s: reverted: %s\n", __func__, func->name);
    }

    BUG_ON(apply_cnt != 1 || revert_cnt != 1);
    printk(KERN_DEBUG "%s: Hook done.\n", __func__);
}

LIVEPATCH_APPLY_HOOK(apply_hook);
LIVEPATCH_REVERT_HOOK(revert_hook);

LIVEPATCH_POSTREVERT_HOOK(post_revert_hook);

struct livepatch_func __section(".livepatch.funcs") livepatch_xen_hello_world = {
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .name = hello_world_patch_this_fnc,
    .new_addr = xen_hello_world,
    .old_addr = xen_extra_version,
    .new_size = NEW_CODE_SZ,
    .old_size = OLD_CODE_SZ,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
