#include "xc_io.h"

void xcio_error(XcIOContext *ctxt, const char *msg, ...){
  va_list args;

  va_start(args, msg);
  IOStream_vprint(ctxt->info, msg, args);
  va_end(args);
}

void xcio_info(XcIOContext *ctxt, const char *msg, ...){
  va_list args;

  if(!(ctxt->flags & XCFLAGS_VERBOSE)) return;
  va_start(args, msg);
  IOStream_vprint(ctxt->info, msg, args);
  va_end(args);
}

void xcio_debug(XcIOContext *ctxt, const char *msg, ...){
  va_list args;

  if(!(ctxt->flags & XCFLAGS_DEBUG)) return;
  va_start(args, msg);
  IOStream_vprint(ctxt->info, msg, args);
  va_end(args);
}
