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

static unsigned int apply_cnt;
static unsigned int revert_cnt;

static int apply_hook(livepatch_payload_t *payload)
{
    int i;

    printk(KERN_DEBUG "%s: Hook starting.\n", __func__);

    for (i = 0; i < payload->nfuncs; i++)
    {
        struct livepatch_func *func = &payload->funcs[i];

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

    BUG_ON(apply_cnt > 0 || revert_cnt > 0);
    printk(KERN_DEBUG "%s: Hook done.\n", __func__);
}

LIVEPATCH_APPLY_HOOK(apply_hook);
LIVEPATCH_REVERT_HOOK(revert_hook);

LIVEPATCH_POSTREVERT_HOOK(post_revert_hook);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
