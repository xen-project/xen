/*
 * Access vector cache interface for the security server.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 */
#ifndef _FLASK_AVC_SS_H_
#define _FLASK_AVC_SS_H_

#include "flask.h"

int avc_ss_reset(u32 seqno);

struct av_perm_to_string {
    u16 tclass;
    u32 value;
    const char *name;
};

struct selinux_class_perm {
    const struct av_perm_to_string *av_perm_to_string;
    u32 av_pts_len;
    u32 cts_len;
    const char **class_to_string;
};

extern const struct selinux_class_perm selinux_class_perm;

#endif /* _FLASK_AVC_SS_H_ */

