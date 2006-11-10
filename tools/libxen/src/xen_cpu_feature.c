/*
 * Copyright (c) 2006, XenSource Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <string.h>

#include "xen_internal.h"
#include "xen_cpu_feature.h"
#include "xen_cpu_feature_internal.h"


/*
 * Maintain this in the same order as the enum declaration!
 */
static const char *lookup_table[] =
{
    "FPU",
    "VME",
    "DE",
    "PSE",
    "TSC",
    "MSR",
    "PAE",
    "MCE",
    "CX8",
    "APIC",
    "SEP",
    "MTRR",
    "PGE",
    "MCA",
    "CMOV",
    "PAT",
    "PSE36",
    "PN",
    "CLFLSH",
    "DTES",
    "ACPI",
    "MMX",
    "FXSR",
    "XMM",
    "XMM2",
    "SELFSNOOP",
    "HT",
    "ACC",
    "IA64",
    "SYSCALL",
    "MP",
    "NX",
    "MMXEXT",
    "LM",
    "3DNOWEXT",
    "3DNOW",
    "RECOVERY",
    "LONGRUN",
    "LRTI",
    "CXMMX",
    "K6_MTRR",
    "CYRIX_ARR",
    "CENTAUR_MCR",
    "K8",
    "K7",
    "P3",
    "P4",
    "CONSTANT_TSC",
    "FXSAVE_LEAK",
    "XMM3",
    "MWAIT",
    "DSCPL",
    "EST",
    "TM2",
    "CID",
    "CX16",
    "XTPR",
    "XSTORE",
    "XSTORE_EN",
    "XCRYPT",
    "XCRYPT_EN",
    "LAHF_LM",
    "CMP_LEGACY",
    "VMX"
};


extern xen_cpu_feature_set *
xen_cpu_feature_set_alloc(size_t size)
{
    return calloc(1, sizeof(xen_cpu_feature_set) +
                  size * sizeof(enum xen_cpu_feature));
}


extern void
xen_cpu_feature_set_free(xen_cpu_feature_set *set)
{
    free(set);
}


const char *
xen_cpu_feature_to_string(enum xen_cpu_feature val)
{
    return lookup_table[val];
}


extern enum xen_cpu_feature
xen_cpu_feature_from_string(xen_session *session, const char *str)
{
    return ENUM_LOOKUP(session, str, lookup_table);
}


const abstract_type xen_cpu_feature_abstract_type_ =
    {
        .typename = ENUM,
        .enum_marshaller =
             (const char *(*)(int))&xen_cpu_feature_to_string,
        .enum_demarshaller =
             (int (*)(xen_session *, const char *))&xen_cpu_feature_from_string
    };


const abstract_type xen_cpu_feature_set_abstract_type_ =
    {
        .typename = SET,
        .child = &xen_cpu_feature_abstract_type_
    };


