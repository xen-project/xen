/*
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 *
 * This file is part of libxl, and was originally taken from libfdt.
 *
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
 * Additionally, this particular file is dual licensed.  That is,
 * alternatively, at your option:
 *
 *      Redistribution and use in source and binary forms, with or
 *      without modification, are permitted provided that the following
 *      conditions are met:
 *
 *      1. Redistributions of source code must retain the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer.
 *      2. Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials
 *         provided with the distribution.
 *
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *      CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *      INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *      MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *      DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *      CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *      NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *      LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *      HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *      CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *      OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *      EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this applies only to this file, and other files with a
 * similar notice.  Also, note that when the same code is distributed
 * along with the rest of libxl, you must comply with the terms of the
 * LGPLv2.1 for the whole of libxl including this file.
 *
 * The intent is to permit, in particular, upstream libfdt to
 * incorporate improvements to this file within upstream libfdt.  At
 * the time of writing, upstream libfdt is dual licensed: 2-clause BSD
 * (as above) and GPLv2-or-later.  The 2-clause BSD licence is
 * compatible with both GPLv2-or-later and LGPLv2.1-only; this permits
 * copying in both directions, and the optional licence upgrade to a
 * copyleft licence by libdft upstream or the Xen Project,
 * respectively.
 */

#include <libfdt.h>

#include "libxl_libfdt_compat.h"

#ifndef HAVE_FDT_FIRST_SUBNODE
_hidden int fdt_first_subnode(const void *fdt, int offset)
{
	int depth = 0;

	offset = fdt_next_node(fdt, offset, &depth);
	if (offset < 0 || depth != 1)
		return -FDT_ERR_NOTFOUND;

	return offset;
}
#endif

#ifndef HAVE_FDT_NEXT_SUBNODE
_hidden int fdt_next_subnode(const void *fdt, int offset)
{
	int depth = 1;

	/*
	 * With respect to the parent, the depth of the next subnode will be
	 * the same as the last.
	 */
	do {
		offset = fdt_next_node(fdt, offset, &depth);
		if (offset < 0 || depth < 1)
			return -FDT_ERR_NOTFOUND;
	} while (depth > 1);

	return offset;
}
#endif
