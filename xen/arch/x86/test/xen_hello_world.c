/*
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
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
static unsigned int cnt;

static void apply_hook(void)
{
    printk(KERN_DEBUG "Hook executing.\n");
}

static void revert_hook(void)
{
    printk(KERN_DEBUG "Hook unloaded.\n");
}

static void  hi_func(void)
{
    printk(KERN_DEBUG "%s: Hi! (called %u times)\n", __func__, ++cnt);
};

static void check_fnc(void)
{
    printk(KERN_DEBUG "%s: Hi func called %u times\n", __func__, cnt);
    BUG_ON(cnt == 0 || cnt > 2);
}

LIVEPATCH_LOAD_HOOK(apply_hook);
LIVEPATCH_UNLOAD_HOOK(revert_hook);

/* Imbalance here. Two load and three unload. */

LIVEPATCH_LOAD_HOOK(hi_func);
LIVEPATCH_UNLOAD_HOOK(hi_func);

LIVEPATCH_UNLOAD_HOOK(check_fnc);

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
