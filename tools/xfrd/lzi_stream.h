/*
 * Copyright (C) 2003 Hewlett-Packard Company.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _XUTIL_LZI_STREAM_H_
#define _XUTIL_LZI_STREAM_H_

#ifndef __KERNEL__
#include "iostream.h"

extern IOStream *lzi_stream_new(IOStream *io, const char *mode);
extern IOStream *lzi_stream_fopen(const char *file, const char *mode);
extern IOStream *lzi_stream_fdopen(int fd, const char *mode);
extern IOStream *lzi_stream_io(IOStream *zio);

extern int lzi_stream_plain_bytes(IOStream *io);
extern int lzi_stream_comp_bytes(IOStream *io);
extern float lzi_stream_ratio(IOStream *io);

#endif
#endif /* !_XUTIL_LZI_STREAM_H_ */
