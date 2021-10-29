#ifndef XSM_FLASK_PRIVATE
#define XSM_FLASK_PRIVATE

#include <public/xen.h>

long do_flask_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op);
int compat_flask_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op);

#endif /* XSM_FLASK_PRIVATE */
