/*
 * Copyright (C) 2004 Mike Wray <mike.wray@hp.com>.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or  (at your option) any later version. This library is 
 * distributed in the  hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#ifndef _XEN_LIB_MARSHAL_H_
#define _XEN_LIB_MARSHAL_H_

#include "iostream.h"

/** A 16-bit uint in network order, e.g. a port number. */
typedef uint16_t net16_t;

/** A 32-bit uint in network order, e.g. an IP address. */
typedef uint32_t net32_t;

extern int marshal_flush(IOStream *io);

extern int marshal_bytes(IOStream *io, void *s, uint32_t s_n);
extern int unmarshal_bytes(IOStream *io, void *s, uint32_t s_n);

extern int marshal_uint8(IOStream *io, uint8_t x);
extern int unmarshal_uint8(IOStream *io, uint8_t *x);

extern int marshal_uint16(IOStream *io, uint16_t x);
extern int unmarshal_uint16(IOStream *io, uint16_t *x);

extern int marshal_uint32(IOStream *io, uint32_t x);
extern int unmarshal_uint32(IOStream *io, uint32_t *x);

extern int marshal_int32(IOStream *io, int32_t x);
extern int unmarshal_int32(IOStream *io, int32_t *x);

extern int marshal_uint64(IOStream *io, uint64_t x);
extern int unmarshal_uint64(IOStream *io, uint64_t *x);

extern int marshal_net16(IOStream *io, net16_t x);
extern int unmarshal_net16(IOStream *io, net16_t *x);

extern int marshal_net32(IOStream *io, net32_t x);
extern int unmarshal_net32(IOStream *io, net32_t *x);

extern int marshal_string(IOStream *io, char *s, uint32_t s_n);
extern int unmarshal_string(IOStream *io, char *s, uint32_t s_n);
extern int unmarshal_new_string(IOStream *io, char **s, uint32_t *s_n);

#endif /* ! _XEN_LIB_MARSHAL_H_ */
