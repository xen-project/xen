/* $Id: xdr.h,v 1.2 2003/09/29 13:40:00 mjw Exp $ */
#ifndef _SP_XDR_H_
#define _SP_XDR_H_
#include "iostream.h"
#include "sxpr.h"
int pack_uint(IOStream *out, unsigned int x);
int unpack_uint(IOStream *in, unsigned int *x);
int pack_string(IOStream *out, Sxpr x);
int unpack_string(IOStream *in, Sxpr *x);
int pack_cons(IOStream *out, Sxpr x);
int unpack_cons(IOStream *in, Sxpr *x);
int pack_sxpr(IOStream *out, Sxpr x);
int unpack_sxpr(IOStream *in, Sxpr *x);
#endif /* _SP_XDR_H_ */
