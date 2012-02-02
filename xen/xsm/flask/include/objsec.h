/*
 *  NSA Security-Enhanced Linux (SELinux) security module
 *
 *  This file contains the Flask security data structures for xen objects.
 *
 *  Author(s):  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */

#ifndef _FLASK_OBJSEC_H_
#define _FLASK_OBJSEC_H_

#include <xen/sched.h>
#include "flask.h"
#include "avc.h"

struct domain_security_struct {
    u32 sid;               /* current SID */
    u32 create_sid;
};

struct evtchn_security_struct {
    u32 sid;                 /* current SID */
};

extern unsigned int selinux_checkreqprot;

#endif /* _FLASK_OBJSEC_H_ */
