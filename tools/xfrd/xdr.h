#ifndef _XUTIL_XDR_H_
#define _XUTIL_XDR_H_
#include "iostream.h"
#include "sxpr.h"

int pack_type(IOStream *io, unsigned short x);

int unpack_type(IOStream *io, unsigned short *x);

int pack_bool(IOStream *io, int x);

int unpack_bool(IOStream *io, int *x);

int pack_uint(IOStream *out, unsigned int x);

int unpack_uint(IOStream *in, unsigned int *x);

int pack_string(IOStream *out, Sxpr x);

int unpack_string(IOStream *in, Sxpr *x);

int pack_cons(IOStream *out, Sxpr x);

int unpack_cons(IOStream *in, Sxpr *x);

int pack_sxpr(IOStream *out, Sxpr x);

int unpack_sxpr(IOStream *in, Sxpr *x);

#endif /* _XUTIL_XDR_H_ */
