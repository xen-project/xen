/*
 * Copyright (c) 2019 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 */

#include <xen/lib.h>
#include <xen/types.h>
#include <xen/version.h>
#include <xen/livepatch.h>
#include <xen/livepatch_payload.h>

#include <public/sysctl.h>

static const char livepatch_exceptions_str[] = "xen_extra_version";
extern const char *xen_hello_world(void);

#define EXPECT_BYTES_COUNT 6

struct livepatch_func __section(".livepatch.funcs") livepatch_exceptions = {
    .version = LIVEPATCH_PAYLOAD_VERSION,
    .name = livepatch_exceptions_str,
    .new_addr = xen_hello_world,
    .old_addr = xen_extra_version,
    .new_size = EXPECT_BYTES_COUNT,
    .old_size = EXPECT_BYTES_COUNT,
    .expect = {
        .enabled = 1,
        .len = EXPECT_BYTES_COUNT,
        .data = { 0xDE, 0xAD, 0xC0, 0xDE, 0xBA, 0xBE }
    },

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
