#ifndef XSM_FLASK_PRIVATE
#define XSM_FLASK_PRIVATE

#include <public/xen.h>

long cf_check do_flask_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op);
int cf_check compat_flask_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op);

#endif /* XSM_FLASK_PRIVATE */
