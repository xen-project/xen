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
#define POLICYDB_VERSION_RANGETRANS	21
#define POLICYDB_VERSION_POLCAP		22
#define POLICYDB_VERSION_PERMISSIVE	23
#define POLICYDB_VERSION_BOUNDARY	24
#define POLICYDB_VERSION_FILENAME_TRANS	25
#define POLICYDB_VERSION_ROLETRANS	26
#define POLICYDB_VERSION_NEW_OBJECT_DEFAULTS	27
#define POLICYDB_VERSION_DEFAULT_TYPE	28
#define POLICYDB_VERSION_CONSTRAINT_NAMES	29
#define POLICYDB_VERSION_XEN_DEVICETREE 30

/* Range of policy versions we understand*/
#define POLICYDB_VERSION_MIN   POLICYDB_VERSION_BASE
#define POLICYDB_VERSION_MAX   POLICYDB_VERSION_XEN_DEVICETREE

enum flask_bootparam_t {
    FLASK_BOOTPARAM_PERMISSIVE,
    FLASK_BOOTPARAM_ENFORCING,
    FLASK_BOOTPARAM_LATELOAD,
    FLASK_BOOTPARAM_DISABLED,
    FLASK_BOOTPARAM_INVALID,
};

extern enum flask_bootparam_t flask_bootparam;
extern int flask_mls_enabled;

int security_load_policy(void * data, size_t len);

struct av_decision {
    u32 allowed;
    u32 auditallow;
    u32 auditdeny;
    u32 seqno;
    u32 flags;
};

/* definitions of av_decision.flags */
#define AVD_FLAGS_PERMISSIVE	0x0001

int security_compute_av(u32 ssid, u32 tsid, u16 tclass, u32 requested,
                                                    struct av_decision *avd);

int security_transition_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);

int security_member_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);

int security_change_sid(u32 ssid, u32 tsid, u16 tclass, u32 *out_sid);

int security_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);

int security_context_to_sid(char *scontext, u32 scontext_len, u32 *out_sid);

int security_get_user_sids(u32 callsid, char *username, u32 **sids, u32 *nel);

int security_irq_sid(int pirq, u32 *out_sid);

int security_iomem_sid(unsigned long, u32 *out_sid);

int security_ioport_sid(u32 ioport, u32 *out_sid);

int security_device_sid(u32 device, u32 *out_sid);

int security_devicetree_sid(const char *path, u32 *out_sid);

int security_validate_transition(u32 oldsid, u32 newsid, u32 tasksid,
                                                                    u16 tclass);

typedef int (*security_iterate_fn)(void *data, u32 sid, unsigned long start,
                                                        unsigned long end);
int security_iterate_iomem_sids(unsigned long start, unsigned long end,
                                security_iterate_fn fn, void *data);

int security_iterate_ioport_sids(u32 start, u32 end,
                                security_iterate_fn fn, void *data);

int security_ocontext_add(u32 ocontext, unsigned long low,
                           unsigned long high, u32 sid);

int security_ocontext_del(u32 ocontext, unsigned long low, unsigned long high);

int security_devicetree_setlabel(char *path, u32 sid);
#endif /* _FLASK_SECURITY_H_ */
