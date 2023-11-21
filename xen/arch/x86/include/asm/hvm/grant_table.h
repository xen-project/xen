/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asm-x86/hvm/grant_table.h
 *
 * Grant table interfaces for HVM guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 */

#ifndef __X86_HVM_GRANT_TABLE_H__
#define __X86_HVM_GRANT_TABLE_H__

#include <xen/mm-frame.h>

#ifdef CONFIG_HVM

int create_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                             unsigned int flags,
                             unsigned int cache_flags);
int replace_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                              uint64_t new_addr, unsigned int flags);

#else

#include <public/grant_table.h>

static inline int create_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                                           unsigned int flags,
                                           unsigned int cache_flags)
{
    return GNTST_general_error;
}

static inline int replace_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                                            uint64_t new_addr, unsigned int flags)
{
    return GNTST_general_error;
}

#endif

#endif /* __X86_HVM_GRANT_TABLE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
