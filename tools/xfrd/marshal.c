#include <errno.h>
#include "sys_net.h"
#include "allocate.h"
#include "marshal.h"

#define dprintf(fmt, args...) IOStream_print(iostdout, "[DEBUG] %s" fmt, __FUNCTION__, ##args)
#define wprintf(fmt, args...) IOStream_print(iostderr, "[WARN]  %s" fmt, __FUNCTION__, ##args)
#define iprintf(fmt, args...) IOStream_print(iostdout, "[INFO]  %s" fmt, __FUNCTION__, ##args)
#define eprintf(fmt, args...) IOStream_print(iostderr, "[ERROR] %s" fmt, __FUNCTION__, ##args)


#define ARRAY_SIZE(ary) (sizeof(ary)/sizeof((ary)[0]))

/* Messages are coded as msgid followed by message fields.
 * Initial message on any channel is hello - so can check version
 * compatibility.
 *
 * char* -> uint16_t:n <n bytes>
 * ints/uints go as suitable number of bytes (e.g. uint16_t is 2 bytes).
 * optional fields go as '1' <val> or '0' (the 0/1 is 1 byte).
 * lists go as ('1' <elt>)* '0'
 */

int marshal_flush(IOStream *io){
    int err  = 0;
    err = IOStream_flush(io);
    return err;
}

int marshal_bytes(IOStream *io, void *s, uint32_t s_n){
    int err = 0;
    int n;
    n = IOStream_write(io, s, s_n);
    if(n < 0){
        err = n;
    } else if (n < s_n){
        wprintf("> Wanted %d, got %d\n", s_n, n);
        err = -EIO;
    }
    return err;
}

int unmarshal_bytes(IOStream *io, void *s, uint32_t s_n){
    int err = 0;
    int n;
    //dprintf("> s_n=%d\n", s_n);
    n = IOStream_read(io, s, s_n);
    //dprintf("> n=%d\n", n);
    if(n < 0){
        err = n;
    } else if(n < s_n){
        wprintf("> Wanted %d, got %d\n", s_n, n);
        err = -EIO;
    }
    //dprintf("< err=%d\n", err);
    return err;
}

int marshal_uint8(IOStream *io, uint8_t x){
    return marshal_bytes(io, &x, sizeof(x));
}

int unmarshal_uint8(IOStream *io, uint8_t *x){
    return unmarshal_bytes(io, x, sizeof(*x));
}

int marshal_uint16(IOStream *io, uint16_t x){
    x = htons(x);
    return marshal_bytes(io, &x, sizeof(x));
}

int unmarshal_uint16(IOStream *io, uint16_t *x){
    int err = 0;
    err = unmarshal_bytes(io, x, sizeof(*x));
    *x = ntohs(*x);
    return err;
}

int marshal_int32(IOStream *io, int32_t x){
    int err = 0;
    //dprintf("> x=%d\n", x);
    x = htonl(x);
    err = marshal_bytes(io, &x, sizeof(x));
    //dprintf("< err=%d\n", err);
    return err;
}

int unmarshal_int32(IOStream *io, int32_t *x){
    int err = 0;
    //dprintf(">\n");
    err = unmarshal_bytes(io, x, sizeof(*x));
    *x = ntohl(*x);
    //dprintf("< err=%d x=%d\n", err, *x);
    return err;
}

int marshal_uint32(IOStream *io, uint32_t x){
    int err = 0;
    //dprintf("> x=%u\n", x);
    x = htonl(x);
    err = marshal_bytes(io, &x, sizeof(x));
    //dprintf("< err=%d\n", err);
    return err;
}

int unmarshal_uint32(IOStream *io, uint32_t *x){
    int err = 0;
    //dprintf(">\n");
    err = unmarshal_bytes(io, x, sizeof(*x));
    *x = ntohl(*x);
    //dprintf("< err=%d x=%u\n", err, *x);
    return err;
}

int marshal_uint64(IOStream *io, uint64_t x){
    int err;
    err = marshal_uint32(io, (uint32_t) ((x >> 32) & 0xffffffff));
    if(err) goto exit;
    err = marshal_uint32(io, (uint32_t) ( x        & 0xffffffff));
  exit:
    return err;
}

int unmarshal_uint64(IOStream *io, uint64_t *x){
    int err = 0;
    uint32_t hi, lo;
    err = unmarshal_uint32(io, &hi);
    if(err) goto exit;
    err = unmarshal_uint32(io, &lo);
    *x = (((uint64_t) hi) << 32) | lo;
  exit:
    return err;
}

int marshal_net16(IOStream *io, net16_t x){
    return marshal_bytes(io, &x, sizeof(x));
}

int unmarshal_net16(IOStream *io, net16_t *x){
    int err = 0;
    err = unmarshal_bytes(io, x, sizeof(*x));
    return err;
}

int marshal_net32(IOStream *io, net32_t x){
    return marshal_bytes(io, &x, sizeof(x));
}

int unmarshal_net32(IOStream *io, net32_t *x){
    int err = 0;
    err = unmarshal_bytes(io, x, sizeof(*x));
    return err;
}

int marshal_string(IOStream *io, char *s, uint32_t s_n){
    int err;
    //dprintf("> s=%s\n", s);
    err = marshal_uint32(io, s_n);
    if(err) goto exit;
    err = marshal_bytes(io, s, s_n);
  exit:
    //dprintf("< err=%d\n", err);
    return err;
}

int unmarshal_string(IOStream *io, char *s, uint32_t s_n){
    int err = 0, val_n = 0;
    //dprintf(">\n");
    err = unmarshal_uint32(io, (unsigned int *)&val_n);
    if(err) goto exit;
    if(val_n >= s_n){
        err = -EINVAL;
        goto exit;
    }
    err = unmarshal_bytes(io, s, val_n);
    if(err) goto exit;
    s[val_n] = '\0';
  exit:
    //dprintf("< err=%d s=%s\n", err, s);
    return err;
}

int unmarshal_new_string(IOStream *io, char **s, uint32_t *s_n){
    int err = 0, val_n = 0;
    char *val = NULL;
    //dprintf(">\n");
    err = unmarshal_uint32(io, (unsigned int *)&val_n);
    if(err) goto exit;
    val = allocate(val_n + 1);
    if(!val){
        err = -ENOMEM;
        goto exit;
    }
    err = unmarshal_bytes(io, val, val_n);
    if(err) goto exit;
    val[val_n] = '\0';
  exit:
    if(err){
        if(val) deallocate(val);
        val = NULL;
        val_n = 0;
    }
    *s = val;
    if(s_n) *s_n = val_n;
    //dprintf("< err=%d s=%s\n", err, *s);
    return err;
}
