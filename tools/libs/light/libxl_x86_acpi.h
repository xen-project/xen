/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
 */

#ifndef LIBXL_X86_ACPI_H
#define LIBXL_X86_ACPI_H

#include "libxl_internal.h"

#define ASSERT(x) assert(x)

static inline int test_bit(unsigned int b, const void *p)
{
    return !!(((const uint8_t *)p)[b>>3] & (1u<<(b&7)));
}

#endif /* LIBXL_X_86_ACPI_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
