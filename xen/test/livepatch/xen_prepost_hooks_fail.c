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

/* This hook always fail and should prevent from loading the livepatch. */
static int pre_apply_hook(livepatch_payload_t *payload)
{
    int i;

    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);

    for (i = 0; i < payload->nfuncs; i++)
    {
        struct livepatch_func *func = &payload->funcs[i];

        printk(KERN_DEBUG "%s: pre applying: %s\n", __func__, func->name);
    }

    printk(KERN_DEBUG "%s: Hook done.\n", __func__);

    return -EINVAL;
}

static int unreachable_pre_hook(livepatch_payload_t *payload)
{
    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);
    BUG();
    printk(KERN_DEBUG "%s: Hook done.\n", __func__);

    return -EINVAL;
}

static void unreachable_post_hook(livepatch_payload_t *payload)
{
    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);
    BUG();
    printk(KERN_DEBUG "%s: Hook done.\n", __func__);
}

LIVEPATCH_PREAPPLY_HOOK(pre_apply_hook);
LIVEPATCH_POSTAPPLY_HOOK(unreachable_post_hook);
LIVEPATCH_PREREVERT_HOOK(unreachable_pre_hook);
LIVEPATCH_POSTREVERT_HOOK(unreachable_post_hook);

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
