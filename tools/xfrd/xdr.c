#include <errno.h>
#include "xdr.h"

#define MODULE_NAME "XDR"
//#define DEBUG 1
#undef DEBUG
#include "debug.h"

/** @file
 * XDR packer/unpacker for elements.
 *
 * string -> [T_STRING] [len:u16] <len bytes>
 * atom   -> [T_ATOM]   [len:u16] <len bytes>
 * uint   -> [T_UINT]   [value]
 * cons   -> [T_LIST]   {1 elt}* 0
 * null   -> [T_NULL]
 * none   -> [T_NONE]
 * bool   -> [T_BOOL]   { 0:u8 | 1:u8 }
 *
 * types packed as u16.
 *
 * So (a b c) -> [T_CONS] a [T_CONS] b [T_CONS] c [T_NULL]
 *    ()      -> [T_NULL]
 */

int pack_bool(IOStream *io, int x){
    int err=0;
    //dprintf("> x=%d\n", x);
    err = IOStream_print(io, "%c", 0xff & x);
    if(err > 0) err = 0;
    //dprintf("< err=%d\n", err);
    return err;
}

int unpack_bool(IOStream *io, int *x){
    int err = 0;
    int c;
    //dprintf(">\n");
    c = IOStream_getc(io);
    *x = (c < 0 ? 0 : c);
    err = IOStream_error(io);
    if(c < 0 && !err) err = -EIO;
    //dprintf("< err=%d x=%d\n", err, *x);
    return err;
}

int pack_ushort(IOStream *io, unsigned short x){
    int err=0;
    //dprintf("> x=%u\n", x);
    err = IOStream_print(io, "%c%c",
                         0xff & (x >>  8),
                         0xff & (x      ));
    if(err > 0) err = 0;
    //dprintf("< err=%d\n", err);
    return err;
}

int unpack_ushort(IOStream *io, unsigned short *x){
    int err = 0;
    int i, c = 0;
    //dprintf(">\n");
    *x = 0;
    for(i = 0; i< 2; i++){
        c = IOStream_getc(io);
        if(c < 0) break;
        *x <<= 8;
        *x |= (0xff & c);
    }
    err = IOStream_error(io);

    if(c < 0 && !err) err = -EIO;
    //dprintf("< err=%d x=%u\n", err, *x);
    return err;
}

int pack_type(IOStream *io, unsigned short x){
    return pack_ushort(io, x);
}

int unpack_type(IOStream *io, unsigned short *x){
    return unpack_ushort(io, x);
}

int pack_uint(IOStream *io, unsigned int x){
    int err=0;
    //dprintf("> x=%u\n", x);
    err = IOStream_print(io, "%c%c%c%c",
                         0xff & (x >> 24),
                         0xff & (x >> 16),
                         0xff & (x >>  8),
                         0xff & (x      ));
    if(err > 0) err = 0;
    //dprintf("< err=%d\n", err);
    return err;
}

int unpack_uint(IOStream *io, unsigned int *x){
    int err = 0;
    int i, c = 0;
    //dprintf(">\n");
    *x = 0;
    for(i = 0; i< 4; i++){
        c = IOStream_getc(io);
        if(c < 0) break;
        *x <<= 8;
        *x |= (0xff & c);
    }
    err = IOStream_error(io);
    if(c < 0 && !err) err = -EIO;
    //dprintf("< err=%d x=%u\n", err, *x);
    return err;
}

int pack_string(IOStream *io, Sxpr x){
    int err = 0;
    unsigned short n = 0xffff & string_length(x);
    char *s = string_string(x);
    int i;
    //dprintf("> n=%d s=%s\n", n, s);
    err = pack_ushort(io, n);
    if(err) goto exit;
    for(i = 0; i < n; i++){
        err = IOStream_print(io, "%c", s[i]);
        if(err < 0) break;
    }
    if(err > 0) err = 0;
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

int unpack_string(IOStream *io, Sxpr *x){
    int err;
    unsigned short n;
    int i, c = 0;
    char *s;
    Sxpr val = ONONE;
    
    //dprintf(">\n");
    err = unpack_ushort(io, &n);
    if(err) goto exit;
    val = halloc(n+1, T_STRING);
    if(NOMEMP(val)){
        err = -ENOMEM;
        goto exit;
    }
    s = string_string(val);
    for(i=0; i<n; i++){
        c = IOStream_getc(io);
        if(c < 0) break;
        s[i] = (char)c;
    }
    s[n] = '\0';
  exit:
    err = IOStream_error(io);
    if(c < 0 && !err) err = -EIO;
    if(err){
        objfree(val);
        val = ONONE;
    }
    *x = val;
    //IOStream_print(iostdout, "n=%d str=", n); 
    //objprint(iostdout, *x, 0);
    //IOStream_print(iostdout, "\n");
    //dprintf("< err=%d\n", err);
    return err;
}

int pack_cons(IOStream *io, Sxpr x){
    int err = 0;
    Sxpr l;
    //dprintf(">\n");
    for(l = x; CONSP(l); l = CDR(l)){
        err = pack_bool(io, 1);
        if(err) goto exit;
        err = pack_sxpr(io, CAR(l));
        if(err) goto exit;
    }
    err = pack_bool(io, 0);
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

int unpack_cons(IOStream *io, Sxpr *x){
    int err = 0;
    int more = 0;
    Sxpr u = ONONE, v = ONONE, val = ONULL;

    dprintf(">\n");
    while(1){
        err = unpack_bool(io, &more);
        if(err) goto exit;
        if(!more){
            //IOStream_print(iostdout, "unpack_cons 1 val=");
            ////objprint(iostdout, val, 0);
            IOStream_print(iostdout, "\n");

            val = nrev(val);

            //IOStream_print(iostdout, "unpack_cons 2 val=");
            //objprint(iostdout, val, 0);
            //IOStream_print(iostdout, "\n");

            break;
        }
        err = unpack_sxpr(io, &u);
        if(err) goto exit;
        v = cons_new(u, val);
        if(NOMEMP(v)){
            err = -ENOMEM;
            objfree(u);
            goto exit;
        }
        val = v;
    }
  exit:
    if(err){
        objfree(val);
        val = ONONE;
    }
    *x = val;
    dprintf("< err=%d\n", err);
    return err;
}
    
int pack_sxpr(IOStream *io, Sxpr x){
    int err = 0;
    unsigned short type = get_type(x);
    //dprintf(">\n");
    //objprint(iostdout, x, 0);
    //IOStream_print(iostdout, "\n");

    err = pack_type(io, type);
    if(err) goto exit;
    switch(type){
    case T_NULL:
        break;
    case T_NONE:
        break;
    case T_BOOL:
        err = pack_bool(io, get_ul(x));
        break;
    case T_CONS:
        err = pack_cons(io, x);
        break;
    case T_ATOM:
        err = pack_string(io, OBJ_ATOM(x)->name);
        break;
    case T_STRING:
        err = pack_string(io, x);
        break;
    case T_UINT:
        err = pack_uint(io, get_ul(x));
        break;
    default:
        err = -EINVAL;
        IOStream_print(iostderr, "%s> invalid type %d\n", __FUNCTION__, type);
        break;
    }
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

int unpack_sxpr(IOStream *io, Sxpr *x){
    int err = 0;
    unsigned short type;
    unsigned int u;
    Sxpr val = ONONE, y;

    //dprintf(">\n");
    err = unpack_type(io, &type);
    if(err) goto exit;
    switch(type){
    case T_NULL:
        val = ONULL;
        break;
    case T_NONE:
        val = ONONE;
        break;
    case T_CONS:
        err = unpack_cons(io, &val);
        break;
    case T_BOOL:
        err = unpack_bool(io, (int *)&u);
        if(err) goto exit;
        val = (u ? OTRUE : OFALSE);
        break;
    case T_ATOM:
        err = unpack_string(io, &y);
        if(err) goto exit;
        val = intern(string_string(y));
        objfree(y);
        break;
    case T_STRING:
        err = unpack_string(io, &val);
        break;
    case T_UINT:
        err = unpack_uint(io, &u);
        if(err) goto exit;
        val = OBJI(type, u);
        break;
    default:
        err = -EINVAL;
        IOStream_print(iostderr, "%s> invalid type %d\n", __FUNCTION__, type);
        break;
    }
  exit:
    *x = (err ? ONONE : val);
    //IOStream_print(iostdout, "sxpr="); 
    //objprint(iostdout, *x, 0);
    //IOStream_print(iostdout, "\n");
    //dprintf("< err=%d\n", err);
    return err;
}
