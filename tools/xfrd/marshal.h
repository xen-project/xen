#ifndef _XUTIL_MARSHAL_H_
#define _XUTIL_MARSHAL_H_

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

#endif /* ! _XUTIL_MARSHAL_H_ */
