#ifndef XSM_FLASK_PRIVATE
#define XSM_FLASK_PRIVATE

#include <public/xen.h>

int cf_check flask_do_xsm_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op);
int cf_check flask_do_compat_op(XEN_GUEST_HANDLE_PARAM(void) u_flask_op);

#endif /* XSM_FLASK_PRIVATE */
