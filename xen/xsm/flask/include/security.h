/*
 * Security server interface.
 *
 * Author : Stephen Smalley, <sds@epoch.ncsc.mil>
 *
 */

/* Ported to Xen 3.0, George Coker, <gscoker@alpha.ncsc.mil> */

#ifndef _FLASK_SECURITY_H_
#define _FLASK_SECURITY_H_

#include "flask.h"

#define SECSID_NULL            0x00000000 /* unspecified SID */
#define SECSID_WILD            0xffffffff /* wildcard SID */
#define SECCLASS_NULL            0x0000 /* no class */

#define FLASK_MAGIC 0xf97cff8c

/* Identify specific policy version changes */
#define POLICYDB_VERSION_BASE        15
#define POLICYDB_VERSION_BOOL        16
#define POLICYDB_VERSION_IPV6        17
#define POLICYDB_VERSION_NLCLASS    18
#define POLICYDB_VERSION_VALIDATETRANS    19
#define POLICYDB_VERSION_MLS        19
#define POLICYDB_VERSION_AVTAB        20

/* Range of policy versions we understand*/
#define POLICYDB_VERSION_MIN   POLICYDB_VERSION_BASE
#define POLICYDB_VERSION_MAX   POLICYDB_VERSION_AVTAB

#ifdef FLASK_BOOTPARAM
extern int flask_enabled;
#else
#define flask_enabled 1
#endif

extern int flask_mls_enabled;

int security_load_policy(void * data, size_t len);

struct av_decision {
    u32 allowed;
    u32 decided;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
};

int security_compute_av(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                                    struct av_decision *avd);

int security_transition_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);

int security_member_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);

int security_change_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);

int security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);

int security_context_to_sid(char *scontext, u32 scontext_len, u32 *out_sid);

int security_context_to_sid_default(char *scontext, u32 scontext_len, 
                                                    u32 *out_sid, u32 def_sid);

int security_get_user_sids(u32 callsid, char *username, u32 **sids, u32 *nel);

int security_pirq_sid(int pirq, u32 *out_sid);

int security_virq_sid(int virq, u32 *out_sid);

int security_vcpu_sid(int vcpu, u32 *out_sid);

int security_iomem_sid(unsigned long, u32 *out_sid);

int security_ioport_sid(u32 ioport, u32 *out_sid);

int security_validate_transition(u32 oldsid, u32 newsid, u32 tasksid,
                                                                    u16 tclass);

#endif /* _FLASK_SECURITY_H_ */
