#ifndef _XFRD_XFRD_H_
#define _XFRD_XFRD_H_

/** Xend port in host order. */
#define XEND_PORT 8000

/** Xfrd port in host order. */
#define XFRD_PORT 8002

/** Protocol version. */
#define XFR_PROTO_MAJOR   1
#define XFR_PROTO_MINOR   0

struct Conn;
extern int xfr_vm_suspend(struct Conn *xend, uint32_t vmid);
extern int xfr_vm_destroy(struct Conn *xend, uint32_t vmid);
#endif
